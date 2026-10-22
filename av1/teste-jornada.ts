/**
 * Testes do greencode: jornada completa de usuário (provisionamento → rastreabilidade)
 * + cenários de falha (integridade, queda durante gravação, sessão, validações).
 * Execução: npm test
 */
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import {
  Banco, Journal, ServicoCriptografia, Sessao, PapelUsuario, ValidadorCNPJ, ValidadorDataLote,
  ValidadorMudancaEstado, ValidadorTransicaoStatus, ServicoAutenticacao, FabricaEquipamento, tokenizar, Organizacao,
} from './greencode';

let ok = 0;
function teste(nome: string, fn: () => void): void {
  try { fn(); ok++; console.log(`  ✔ ${nome}`); }
  catch (e) { console.error(`  ✘ ${nome}\n    ${(e as Error).message}`); process.exitCode = 1; }
}
const tmp = (): string => fs.mkdtempSync(path.join(os.tmpdir(), 'greencode-'));
const iso = (d: Date): string => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
const somarDias = (n: number): string => { const d = new Date(); d.setDate(d.getDate() + n); return iso(d); };

function rodar(dir: string, linhas: string[]): { saida: string; codigo: number } {
  const r = spawnSync(process.execPath, [path.join(__dirname, 'greencode.js'), '--dir', dir], {
    input: linhas.join('\n') + '\n', encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' },
  });
  return { saida: (r.stdout ?? '') + (r.stderr ?? ''), codigo: r.status ?? -1 };
}

console.log('\n== Testes unitários ==');

teste('CNPJ: válido, inválido, repetido e formato', () => {
  const v = new ValidadorCNPJ();
  assert.ok(v.validar('11.222.333/0001-81').ok);
  assert.ok(v.validar('11444777000161').ok);
  assert.ok(!v.validar('11.222.333/0001-82').ok);
  assert.ok(!v.validar('11111111111111').ok);
  assert.ok(!v.validar('123').ok);
});

teste('Lote: data futura e anterior a 90 dias são recusadas', () => {
  const v = new ValidadorDataLote();
  assert.ok(v.validar(somarDias(0)).ok);
  assert.ok(v.validar(somarDias(-90)).ok);
  assert.ok(!v.validar(somarDias(-91)).ok);
  assert.ok(!v.validar(somarDias(1)).ok);
  assert.ok(!v.validar('31/02/2026').ok);
});

teste('Estado físico: queda de 2+ categorias exige justificativa', () => {
  const v = new ValidadorMudancaEstado();
  assert.ok(v.validar({ de: 'BOM', para: 'REGULAR' }).ok);
  assert.ok(!v.validar({ de: 'BOM', para: 'RUIM' }).ok);
  assert.ok(v.validar({ de: 'BOM', para: 'RUIM', justificativa: 'Placa-mãe oxidada' }).ok);
  assert.ok(v.validar({ de: 'RUIM', para: 'EXCELENTE' }).ok);
});

teste('Desmonte só após triagem completa', () => {
  const v = new ValidadorTransicaoStatus();
  assert.ok(!v.validar({ atual: 'RECEBIDO', para: 'EM_DESMONTE', triagemCompleta: false }).ok);
  assert.ok(!v.validar({ atual: 'EM_TRIAGEM', para: 'EM_DESMONTE', triagemCompleta: false }).ok);
  assert.ok(!v.validar({ atual: 'TRIADO', para: 'EM_DESMONTE', triagemCompleta: false }).ok);
  assert.ok(v.validar({ atual: 'TRIADO', para: 'EM_DESMONTE', triagemCompleta: true }).ok);
});

teste('Papéis: auditor é somente leitura; polimorfismo de permissões', () => {
  const aud = PapelUsuario.porNome('AUDITOR');
  assert.ok(aud.pode('relatorio:ler') && aud.pode('equip:ler'));
  assert.ok(!aud.pode('equip:escrever') && !aud.pode('org:escrever') && !aud.pode('usuario:gerir'));
  assert.ok(PapelUsuario.porNome('ADMIN').pode('usuario:gerir'));
  assert.ok(!PapelUsuario.porNome('CADASTRO').pode('lote:escrever'));
  assert.ok(!PapelUsuario.porNome('ALMOXARIFADO').pode('org:escrever'));
});

teste('Sessão expira após 30 minutos de inatividade', () => {
  let t = 1_000_000;
  const s = new Sessao('ana', PapelUsuario.porNome('AUDITOR'), 30 * 60_000, () => t);
  t += 29 * 60_000; assert.ok(!s.expirada());
  s.renovar();
  t += 29 * 60_000; assert.ok(!s.expirada());
  t += 2 * 60_000; assert.ok(s.expirada());
});

teste('Tokenizador respeita aspas', () => {
  assert.deepStrictEqual(tokenizar('lote criar --org BR001 --transp "Trans Rapida"'),
    ['lote', 'criar', '--org', 'BR001', '--transp', 'Trans Rapida']);
  assert.throws(() => tokenizar('a "b'));
});

teste('Código de barras tem dígito verificador', () => {
  assert.strictEqual(FabricaEquipamento.codigoBarras(1).length, 11);
});

teste('Hash de senha: salts diferentes → hashes diferentes; verificação correta', () => {
  const a = ServicoAutenticacao.novaCredencial('x', 'ADMIN', 'Senha#Forte123');
  const b = ServicoAutenticacao.novaCredencial('x', 'ADMIN', 'Senha#Forte123');
  assert.notStrictEqual(a.hash, b.hash);
  assert.strictEqual(a.hash.length, 64);
});

console.log('\n== Persistência, criptografia e journal ==');

teste('AES-256-GCM: round-trip e detecção de adulteração', () => {
  const c = new ServicoCriptografia(ServicoCriptografia.gerarChave());
  const x = c.cifrar('segredo', 'a.dat');
  assert.strictEqual(c.decifrar(x, 'a.dat').toString(), 'segredo');
  x[x.length - 1] ^= 0xff;
  assert.throws(() => c.decifrar(x, 'a.dat'), /integridade/i);
  assert.throws(() => c.decifrar(c.cifrar('s', 'a.dat'), 'b.dat'), /integridade/i); // AAD diferente
});

teste('Dados em disco não contêm texto claro', () => {
  const dir = tmp();
  const b = new Banco(dir, new ServicoCriptografia(ServicoCriptografia.gerarChave()));
  b.abrir();
  const org: Organizacao = { id: 'BR001', cnpj: '11222333000181', nome: 'Banco Sigiloso', tipo: 'BANCO', contratos: [], ativa: true, criadoEm: '', criadoPor: 'x' };
  b.executar('T', 'x', 'teste', [{ colecao: 'organizacoes', registro: org }]);
  for (const f of fs.readdirSync(dir)) assert.ok(!fs.readFileSync(path.join(dir, f)).toString('latin1').includes('Sigiloso'), f);
});

teste('Journal: encadeamento válido e detecção de remoção de linha', () => {
  const dir = tmp();
  const b = new Banco(dir, new ServicoCriptografia(ServicoCriptografia.gerarChave()));
  b.abrir();
  for (let i = 0; i < 4; i++) b.evento('E', 'x', `evento ${i}`);
  assert.ok(b.journal.verificar().ok);
  const arq = path.join(dir, 'journal.log');
  const linhas = fs.readFileSync(arq, 'utf8').split('\n').filter(Boolean);
  fs.writeFileSync(arq, [linhas[0], linhas[2], linhas[3]].join('\n') + '\n');
  assert.ok(!b.journal.verificar().ok);
});

teste('Journal: rotação ao ultrapassar o limite e retenção mínima de 180 dias', () => {
  const dir = tmp();
  const c = new ServicoCriptografia(ServicoCriptografia.gerarChave());
  const j = new Journal(dir, c, () => new Date(), 2000, 180);
  j.inicializar();
  for (let i = 0; i < 30; i++) j.append({ tipo: 'EVENTO', operacao: 'E', ator: 'x', resumo: 'r'.repeat(40) });
  const rot = fs.readdirSync(dir).filter((f) => /^journal\..+\.log$/.test(f));
  assert.ok(rot.length >= 1, 'deveria ter rotacionado');
  assert.ok(j.verificar().ok, 'cadeia deve atravessar a rotação');
  // arquivo rotacionado com 100 dias: mantido; com 200 dias: removido
  const velho = path.join(dir, rot[0]);
  const t100 = new Date(Date.now() - 100 * 86_400_000); fs.utimesSync(velho, t100, t100);
  j.purgarAntigos(); assert.ok(fs.existsSync(velho));
  const t200 = new Date(Date.now() - 200 * 86_400_000); fs.utimesSync(velho, t200, t200);
  j.purgarAntigos(); assert.ok(!fs.existsSync(velho));
});

teste('Queda entre INTENT e gravação: recuperação idempotente pelo journal', () => {
  const dir = tmp();
  const chave = ServicoCriptografia.gerarChave();
  const c = new ServicoCriptografia(chave);
  const b1 = new Banco(dir, c); b1.abrir();
  const org: Organizacao = { id: 'BR001', cnpj: '11222333000181', nome: 'Org Recuperada', tipo: 'BANCO', contratos: [], ativa: true, criadoEm: '', criadoPor: 'x' };
  // Simula crash: INTENT gravada no journal, estado ainda não gravado.
  b1.journal.append({ tipo: 'INTENT', tx: 'tx-crash', operacao: 'ORG_CRIAR', ator: 'x', resumo: 'crash', mutacoes: [{ colecao: 'organizacoes', registro: org }] });
  const b2 = new Banco(dir, c); b2.abrir();
  assert.ok(b2.recuperouTransacao);
  assert.strictEqual(b2.organizacoes.obter('BR001')?.nome, 'Org Recuperada');
  const b3 = new Banco(dir, c); b3.abrir();
  assert.ok(!b3.recuperouTransacao, 'não deve recuperar duas vezes');
  assert.ok(b3.journal.verificar().ok);
});

teste('Escrita atômica: arquivos .tmp órfãos são descartados; cauda de journal truncada é tolerada', () => {
  const dir = tmp();
  const c = new ServicoCriptografia(ServicoCriptografia.gerarChave());
  const b = new Banco(dir, c); b.abrir(); b.evento('E', 'x', 'ok');
  fs.writeFileSync(path.join(dir, 'lotes.dat.123.abcd.tmp'), 'lixo');
  fs.appendFileSync(path.join(dir, 'journal.log'), 'AAAA'); // linha pela metade
  const b2 = new Banco(dir, c); b2.abrir();
  assert.ok(!fs.existsSync(path.join(dir, 'lotes.dat.123.abcd.tmp')));
  assert.ok(b2.journal.verificar().ok);
});

console.log('\n== Jornada completa via CLI (stdin → stdout) ==');

const dirE2E = tmp();
const SENHA_ADM = 'Verde#Segura2026';
const hoje = iso(new Date());
const inicio = somarDias(-30), fim = somarDias(365);

const jornada1 = [
  SENHA_ADM, SENHA_ADM,                                   // provisionamento
  'admin', SENHA_ADM,
  'ajuda',
  'usuario criar --nome carla --papel CADASTRO', 'Cad#Segura2026', 'Cad#Segura2026',
  'usuario criar --nome beto --papel ALMOXARIFADO', 'Alm#Segura2026', 'Alm#Segura2026',
  'usuario criar --nome ana --papel AUDITOR', 'Aud#Segura2026', 'Aud#Segura2026',
  'usuario criar --nome fraco --papel AUDITOR', 'abc', 'abc', 'abc', 'abc', 'abc', 'abc',
  'param definir depreciacao.COMPUTADOR 25',
  'logout',
  'carla', 'Cad#Segura2026',
  'org criar --cnpj 11.222.333/0001-81 --nome "Banco Exemplo S.A." --tipo BANCO',
  'org criar --cnpj 11222333000181 --nome "Duplicada" --tipo BANCO',
  'org criar --cnpj 11.222.333/0001-82 --nome "CNPJ Invalido" --tipo BANCO',
  `org contrato BR001 --inicio ${inicio} --fim ${fim} --prazo-dias 60 --descricao "Coleta trimestral"`,
  'usuario listar',
  'lote criar --org BR001 --nf 1 --transp X',
  'logout',
  'beto', 'Alm#Segura2026',
  'ajuda',
  'lote criar --org BR001 --nf 123456 --transp TransRapida',
  `lote criar --org BR001 --nf 123457 --transp TransRapida --data ${somarDias(1)}`,
  `lote criar --org BR001 --nf 123458 --transp TransRapida --data ${somarDias(-91)}`,
  'equip registrar --lote LT-000001 --tipo COMPUTADOR --desc "Desktop Dell" --serie SN12345 --estado BOM',
  'equip registrar --lote LT-000001 --tipo MONITOR --desc "Monitor 24" --serie SN12345',
  'equip mover EQ-000001 --status EM_DESMONTE',
  'equip mover EQ-000001 --status EM_TRIAGEM',
  'equip mover EQ-000001 --status EM_DESMONTE',
  'equip estado EQ-000001 --novo SUCATA',
  'equip triar EQ-000001 --estado RUIM --classe RECICLAVEL',
  'equip triar EQ-000001 --estado RUIM --classe RECICLAVEL --justificativa "Placa-mãe oxidada e fonte danificada"',
  'equip mover EQ-000001 --status EM_DESMONTE',
  'equip mover EQ-000001 --status RECICLADO --obs "Enviado à recicladora"',
  'equip rastrear EQ-000001',
  'equip ver EQ-000001',
  'org criar --cnpj 11.444.777/0001-61 --nome "Outra" --tipo HOSPITAL',
  'logout',
  'ana', 'Aud#Segura2026',
  'ajuda',
  'equip listar',
  'equip mover EQ-000001 --status DESCARTADO',
  'relatorio resumo',
  'relatorio auditoria --dias 1',
  'journal verificar',
  'sair',
];
const r1 = rodar(dirE2E, jornada1);

function esperar(nome: string, saida: string, trecho: string | RegExp): void {
  teste(nome, () => {
    const achou = typeof trecho === 'string' ? saida.includes(trecho) : trecho.test(saida);
    assert.ok(achou, `trecho não encontrado: ${trecho}\n----- saída -----\n${saida.slice(-2500)}`);
  });
}
esperar('provisiona (chave + admin) e cria master.json', r1.saida, 'Provisionamento concluído');
teste('master.json existe e demais arquivos estão cifrados', () => {
  assert.ok(fs.existsSync(path.join(dirE2E, 'master.json')));
  for (const f of ['credenciais.dat', 'organizacoes.dat', 'lotes.dat', 'equipamentos.dat', 'movimentacoes.dat', 'journal.log']) {
    const conteudo = fs.readFileSync(path.join(dirE2E, f)).toString('latin1');
    assert.ok(!conteudo.includes('Banco Exemplo') && !conteudo.includes('TransRapida') && !conteudo.includes('SN12345'), f);
  }
});
esperar('rejeita senha fraca', r1.saida, 'Senha fraca');
esperar('cria organização BR001', r1.saida, 'Organização BR001 cadastrada');
esperar('recusa CNPJ duplicado', r1.saida, 'já cadastrado');
esperar('recusa CNPJ com DV inválido', r1.saida, 'dígitos verificadores não conferem');
esperar('auditor/cadastro sem permissão de usuário', r1.saida, /não permite executar "usuario listar"/);
esperar('cadastro não cria lote', r1.saida, /não permite executar "lote criar"/);
esperar('cria lote LT-000001 (exemplo do enunciado)', r1.saida, 'Lote LT-000001 criado para BR001 (NF 123456, TransRapida');
esperar('recusa lote com data futura', r1.saida, 'Data de entrada futura');
esperar('recusa lote anterior a 90 dias', r1.saida, 'anterior a mais de 90 dias');
esperar('registra equipamento com código de barras', r1.saida, /Equipamento EQ-000001 registrado\. Código de barras: GC\d{9}/);
esperar('recusa série duplicada', r1.saida, 'já registrado');
esperar('recusa desmonte sem triagem', r1.saida, /Transição RECEBIDO → EM_DESMONTE não permitida|após triagem completa/);
esperar('recusa desmonte direto de EM_TRIAGEM', r1.saida, 'Transição EM_TRIAGEM → EM_DESMONTE não permitida');
esperar('exige justificativa para queda de 2 categorias', r1.saida, 'exige --justificativa');
esperar('triagem completa com justificativa', r1.saida, 'EQ-000001 triado como RECICLAVEL');
esperar('desmonte após triagem', r1.saida, 'EQ-000001 agora está EM_DESMONTE');
esperar('rastreabilidade completa', r1.saida, /REGISTRO[\s\S]*STATUS[\s\S]*TRIAGEM[\s\S]*STATUS[\s\S]*STATUS/);
esperar('depreciação paramétrica aplicada (25%)', r1.saida, 'Depreciação anual: 25%');
esperar('gestor não cadastra organização', r1.saida, /não permite executar "org criar"/);
esperar('auditor não altera nada', r1.saida, /não permite executar "equip mover"/);
esperar('auditor gera relatórios', r1.saida, 'Por status:');
esperar('auditoria registra operações', r1.saida, 'EQUIP_TRIAR');
esperar('journal íntegro', r1.saida, /Journal íntegro: \d+ entradas verificadas/);
teste('menu do auditor oculta comandos de escrita', () => {
  const trecho = r1.saida.slice(r1.saida.lastIndexOf('ana@') === -1 ? 0 : r1.saida.indexOf('Bem-vindo(a), ana'));
  assert.ok(!/equip registrar\s/.test(trecho.split('ajuda')[1]?.split('equip listar')[0] ?? ''), 'auditor não deve ver "equip registrar"');
});
teste('encerra com código 0', () => assert.strictEqual(r1.codigo, 0));

console.log('\n== Cenários de falha e persistência entre execuções ==');

const r2 = rodar(dirE2E, ['admin', 'Senha#Errada1', 'admin', SENHA_ADM, 'equip ver EQ-000001', 'param listar', 'sair']);
esperar('credencial inválida é recusada com mensagem genérica', r2.saida, 'Usuário ou senha inválidos.');
esperar('estado persiste entre execuções (cifrado)', r2.saida, 'Lote LT-000001 | estado RUIM | status RECICLADO');
teste('histórico persistente cifrado por usuário', () => {
  assert.ok(fs.existsSync(path.join(dirE2E, 'historico.dat')));
  assert.ok(!fs.readFileSync(path.join(dirE2E, 'historico.dat')).toString('latin1').includes('equip'));
});

const r3 = rodar(dirE2E, ['admin', SENHA_ADM, 'sair']);
teste('trava de instância é liberada ao sair', () => assert.ok(!fs.existsSync(path.join(dirE2E, 'greencode.lock')) && r3.codigo === 0));

// Adulteração de arquivo de dados
const adulterado = tmp();
rodar(adulterado, [SENHA_ADM, SENHA_ADM, 'admin', SENHA_ADM, 'sair']);
const alvo = path.join(adulterado, 'credenciais.dat');
const bytes = fs.readFileSync(alvo); bytes[bytes.length - 3] ^= 0x01; fs.writeFileSync(alvo, bytes);
const r4 = rodar(adulterado, ['admin', SENHA_ADM, 'sair']);
esperar('arquivo adulterado é detectado (integridade GCM)', r4.saida, /\[CRITICO\].*integridade/i);
teste('adulteração resulta em código de saída ≠ 0', () => assert.notStrictEqual(r4.codigo, 0));

// Perda do arquivo mestre
const semMestre = tmp();
rodar(semMestre, [SENHA_ADM, SENHA_ADM, 'admin', SENHA_ADM, 'sair']);
fs.unlinkSync(path.join(semMestre, 'master.json'));
const r5 = rodar(semMestre, [SENHA_ADM, SENHA_ADM, 'sair']);
esperar('master.json ausente com dados existentes não reprovisiona', r5.saida, 'existem dados cifrados');

// Bloqueio por tentativas
const r6 = rodar(tmp(), [SENHA_ADM, SENHA_ADM, ...Array.from({ length: 6 }, () => ['admin', 'Errada#12345']).flat()]);
esperar('bloqueio após tentativas malsucedidas', r6.saida, /Muitas tentativas|bloqueada/);

console.log(`\n${ok} verificações concluídas${process.exitCode ? ' — HÁ FALHAS' : ' com sucesso'}.\n`);
