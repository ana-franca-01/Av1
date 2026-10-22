#!/usr/bin/env node
"use strict";
/**
 * greencode — Núcleo operacional da plataforma de logística reversa de eletrônicos.
 * Atividade de avaliação individual 1 (Node.js + TypeScript, CLI).
 *
 * Principais características:
 *  - Persistência em arquivos cifrados com AES-256-GCM, gravação atômica (tmp + rename).
 *  - Journaling (write-ahead log) imutável e encadeado por hash (SHA-256), com rotação (10 MB)
 *    e retenção mínima de 180 dias.
 *  - Autenticação (PBKDF2-HMAC-SHA256 + salt), sessão com expiração de 30 min de inatividade.
 *  - 4 papéis (administrador, operador de cadastro, gestor de almoxarifado, auditor) com polimorfismo.
 *  - Validações de negócio (CNPJ, datas de lote, triagem, rebaixamento de estado físico).
 *  - CLI com readline: autocompletar, histórico persistente (cifrado, por usuário) e menu adaptativo.
 *
 * Compatível com Windows 10+, Ubuntu 24.04+ e derivados (Node.js >= 18).
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServicoParametros = exports.PARAMETROS_PADRAO = exports.Banco = exports.Journal = exports.Colecao = exports.ValidadorSenha = exports.ValidadorMudancaEstado = exports.ValidadorTransicaoStatus = exports.ValidadorDataLote = exports.ValidadorCNPJ = exports.Validador = exports.FabricaEquipamento = exports.EquipamentoGenerico = exports.Periferico = exports.EquipamentoTelecom = exports.Monitor = exports.Servidor = exports.Computador = exports.Equipamento = exports.PapelAuditor = exports.PapelGestorAlmoxarifado = exports.PapelOperadorCadastro = exports.PapelAdministrador = exports.PapelUsuario = exports.TRANSICOES = exports.CLASSES_TRIAGEM = exports.STATUS = exports.PESO_ESTADO = exports.ESTADOS = exports.TIPOS_EQUIP = exports.TIPOS_ORG = exports.NOMES_PAPEIS = exports.ArmazenamentoCifrado = exports.ServicoCriptografia = exports.Saida = exports.ErroSistema = exports.ErroIntegridade = exports.ErroNaoEncontrado = exports.ErroNegocio = exports.ErroPermissao = exports.ErroValidacao = exports.ErroGreencode = exports.LOTE_MAX_DIAS_RETROATIVO = exports.BLOQUEIO_LOGIN_MS = exports.MAX_FALHAS_LOGIN = exports.PBKDF2_ITERACOES = exports.JOURNAL_RETENCAO_DIAS = exports.JOURNAL_MAX_BYTES = exports.SESSAO_TIMEOUT_MS = exports.VERSAO = void 0;
exports.Aplicacao = exports.Terminal = exports.ArgsComando = exports.ServicoDominio = exports.ServicoAutenticacao = exports.Sessao = void 0;
exports.escreverArquivoAtomico = escreverArquivoAtomico;
exports.tokenizar = tokenizar;
exports.analisarArgumentos = analisarArgumentos;
exports.diretorioPadrao = diretorioPadrao;
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const readline = __importStar(require("readline"));
const stream_1 = require("stream");
// ============================================================================
// 1. CONSTANTES
// ============================================================================
exports.VERSAO = '1.0.0';
exports.SESSAO_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutos de inatividade
exports.JOURNAL_MAX_BYTES = 10 * 1024 * 1024; // 10 MB
exports.JOURNAL_RETENCAO_DIAS = 180;
exports.PBKDF2_ITERACOES = 210000;
exports.MAX_FALHAS_LOGIN = 5;
exports.BLOQUEIO_LOGIN_MS = 5 * 60 * 1000;
exports.LOTE_MAX_DIAS_RETROATIVO = 90;
const HISTORICO_MAX = 500;
// ============================================================================
// 2. UTILITÁRIOS
// ============================================================================
const clonar = (v) => JSON.parse(JSON.stringify(v));
const pad = (n, w) => String(n).padStart(w, '0');
function normalizarEnum(valor, validos, rotulo) {
    const v = valor.trim().toUpperCase().replace(/[\s-]+/g, '_');
    if (!validos.includes(v)) {
        throw new ErroValidacao(`${rotulo} inválido "${valor}". Valores aceitos: ${validos.join(', ')}.`);
    }
    return v;
}
function parseData(s) {
    let m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s.trim());
    let a, mes, d;
    if (m) {
        a = +m[1];
        mes = +m[2];
        d = +m[3];
    }
    else {
        m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(s.trim());
        if (!m)
            return null;
        d = +m[1];
        mes = +m[2];
        a = +m[3];
    }
    const t = new Date(Date.UTC(a, mes - 1, d));
    if (t.getUTCFullYear() !== a || t.getUTCMonth() !== mes - 1 || t.getUTCDate() !== d)
        return null;
    return { a, m: mes, d };
}
const diaOrdinal = (c) => Math.floor(Date.UTC(c.a, c.m - 1, c.d) / 86400000);
const formatarISO = (c) => `${pad(c.a, 4)}-${pad(c.m, 2)}-${pad(c.d, 2)}`;
const hojeCivil = (agora) => ({ a: agora.getFullYear(), m: agora.getMonth() + 1, d: agora.getDate() });
const dataHora = (iso) => {
    const d = new Date(iso);
    return `${pad(d.getFullYear(), 4)}-${pad(d.getMonth() + 1, 2)}-${pad(d.getDate(), 2)} ` +
        `${pad(d.getHours(), 2)}:${pad(d.getMinutes(), 2)}:${pad(d.getSeconds(), 2)}`;
};
function proximoId(col, prefixo, largura) {
    let max = 0;
    const re = new RegExp(`^${prefixo}(\\d+)$`);
    for (const r of col.todos()) {
        const m = re.exec(r.id);
        if (m)
            max = Math.max(max, parseInt(m[1], 10));
    }
    return `${prefixo}${pad(max + 1, largura)}`;
}
/** Grava um arquivo de forma atômica: temporário + fsync + rename. */
function escreverArquivoAtomico(destino, dados) {
    const tmp = `${destino}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
        fs.writeSync(fd, dados, 0, dados.length);
        fs.fsyncSync(fd);
    }
    finally {
        fs.closeSync(fd);
    }
    try {
        fs.renameSync(tmp, destino);
    }
    catch (e) {
        try {
            fs.unlinkSync(tmp);
        }
        catch { /* ignora */ }
        throw e;
    }
    try { // fsync do diretório (POSIX); em Windows não é suportado
        const dfd = fs.openSync(path.dirname(destino), 'r');
        try {
            fs.fsyncSync(dfd);
        }
        finally {
            fs.closeSync(dfd);
        }
    }
    catch { /* melhor esforço */ }
}
class ErroGreencode extends Error {
    constructor(mensagem, severidade = 'ERRO', codigo = 'GC-000') {
        super(mensagem);
        this.severidade = severidade;
        this.codigo = codigo;
        this.name = new.target.name;
    }
}
exports.ErroGreencode = ErroGreencode;
class ErroValidacao extends ErroGreencode {
    constructor(m) { super(m, 'ERRO', 'GC-VAL'); }
}
exports.ErroValidacao = ErroValidacao;
class ErroPermissao extends ErroGreencode {
    constructor(m) { super(m, 'ERRO', 'GC-PERM'); }
}
exports.ErroPermissao = ErroPermissao;
class ErroNegocio extends ErroGreencode {
    constructor(m) { super(m, 'ERRO', 'GC-NEG'); }
}
exports.ErroNegocio = ErroNegocio;
class ErroNaoEncontrado extends ErroGreencode {
    constructor(m) { super(m, 'ERRO', 'GC-404'); }
}
exports.ErroNaoEncontrado = ErroNaoEncontrado;
class ErroIntegridade extends ErroGreencode {
    constructor(m) { super(m, 'CRITICO', 'GC-INT'); }
}
exports.ErroIntegridade = ErroIntegridade;
class ErroSistema extends ErroGreencode {
    constructor(m) { super(m, 'CRITICO', 'GC-SYS'); }
}
exports.ErroSistema = ErroSistema;
const COR = {
    INFO: '\x1b[36m', SUCESSO: '\x1b[32m', AVISO: '\x1b[33m', ERRO: '\x1b[31m', CRITICO: '\x1b[1;97;41m',
};
class Saida {
    constructor(cores = !!process.stdout.isTTY && !process.env.NO_COLOR, destino = (t) => { process.stdout.write(t); }) {
        this.cores = cores;
        this.destino = destino;
    }
    log(sev, msg) {
        const tag = `[${sev}]`;
        this.destino(`${this.cores ? `${COR[sev]}${tag}\x1b[0m` : tag} ${msg}\n`);
    }
    info(m) { this.log('INFO', m); }
    sucesso(m) { this.log('SUCESSO', m); }
    aviso(m) { this.log('AVISO', m); }
    erro(m) { this.log('ERRO', m); }
    critico(m) { this.log('CRITICO', m); }
    linha(t = '') { this.destino(`${t}\n`); }
    tabela(cabecalho, linhas) {
        if (linhas.length === 0) {
            this.linha('  (nenhum registro)');
            return;
        }
        const larg = cabecalho.map((c, i) => Math.max(c.length, ...linhas.map((l) => (l[i] ?? '').length)));
        const fmt = (l) => '  ' + l.map((c, i) => (c ?? '').padEnd(larg[i])).join('  ').trimEnd();
        this.linha(fmt(cabecalho));
        this.linha('  ' + larg.map((w) => '-'.repeat(w)).join('  '));
        linhas.forEach((l) => this.linha(fmt(l)));
    }
}
exports.Saida = Saida;
// ============================================================================
// 4. CRIPTOGRAFIA (AES-256-GCM) E ARMAZENAMENTO ATÔMICO
// ============================================================================
class ServicoCriptografia {
    constructor(chave) {
        this.chave = chave;
        if (chave.length !== 32)
            throw new ErroIntegridade('Chave mestra inválida (esperado 256 bits).');
    }
    static gerarChave() { return crypto.randomBytes(32); }
    /** Formato: MAGIC(3) | IV(12) | TAG(16) | CIFRADO. O AAD vincula o conteúdo ao nome lógico do arquivo. */
    cifrar(dados, aad) {
        const iv = crypto.randomBytes(12);
        const c = crypto.createCipheriv('aes-256-gcm', this.chave, iv);
        c.setAAD(Buffer.from(aad, 'utf8'));
        const ct = Buffer.concat([c.update(typeof dados === 'string' ? Buffer.from(dados, 'utf8') : dados), c.final()]);
        return Buffer.concat([ServicoCriptografia.MAGIC, iv, c.getAuthTag(), ct]);
    }
    decifrar(buf, aad) {
        const M = ServicoCriptografia.MAGIC;
        if (buf.length < M.length + 28 || !buf.subarray(0, M.length).equals(M)) {
            throw new ErroIntegridade(`Formato inválido em "${aad}".`);
        }
        const iv = buf.subarray(3, 15);
        const tag = buf.subarray(15, 31);
        const ct = buf.subarray(31);
        try {
            const d = crypto.createDecipheriv('aes-256-gcm', this.chave, iv);
            d.setAAD(Buffer.from(aad, 'utf8'));
            d.setAuthTag(tag);
            return Buffer.concat([d.update(ct), d.final()]);
        }
        catch {
            throw new ErroIntegridade(`Falha de integridade/autenticidade em "${aad}" (arquivo adulterado ou chave incorreta).`);
        }
    }
    sha256Hex(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }
}
exports.ServicoCriptografia = ServicoCriptografia;
ServicoCriptografia.MAGIC = Buffer.from('GC1');
class ArmazenamentoCifrado {
    constructor(dir, cripto) {
        this.dir = dir;
        this.cripto = cripto;
    }
    caminho(nome) { return path.join(this.dir, nome); }
    existe(nome) { return fs.existsSync(this.caminho(nome)); }
    lerJSON(nome, padrao) {
        if (!this.existe(nome))
            return padrao;
        const txt = this.cripto.decifrar(fs.readFileSync(this.caminho(nome)), nome).toString('utf8');
        try {
            return JSON.parse(txt);
        }
        catch {
            throw new ErroIntegridade(`Conteúdo ilegível em "${nome}".`);
        }
    }
    gravarJSON(nome, valor) {
        escreverArquivoAtomico(this.caminho(nome), this.cripto.cifrar(JSON.stringify(valor), nome));
    }
}
exports.ArmazenamentoCifrado = ArmazenamentoCifrado;
exports.NOMES_PAPEIS = ['ADMIN', 'CADASTRO', 'ALMOXARIFADO', 'AUDITOR'];
exports.TIPOS_ORG = ['VAREJO', 'HOSPITAL', 'UNIVERSIDADE', 'BANCO', 'INDUSTRIA', 'GOVERNO', 'OUTRO'];
exports.TIPOS_EQUIP = ['COMPUTADOR', 'SERVIDOR', 'MONITOR', 'TELECOM', 'PERIFERICO', 'OUTRO'];
exports.ESTADOS = ['EXCELENTE', 'BOM', 'REGULAR', 'RUIM', 'SUCATA'];
exports.PESO_ESTADO = { EXCELENTE: 4, BOM: 3, REGULAR: 2, RUIM: 1, SUCATA: 0 };
exports.STATUS = ['RECEBIDO', 'EM_TRIAGEM', 'TRIADO', 'EM_DESMONTE', 'REUTILIZADO', 'RECICLADO', 'DESCARTADO'];
exports.CLASSES_TRIAGEM = ['REUTILIZAVEL', 'RECICLAVEL', 'DESCARTE_SEGURO'];
exports.TRANSICOES = {
    RECEBIDO: ['EM_TRIAGEM'],
    EM_TRIAGEM: ['TRIADO'],
    TRIADO: ['EM_DESMONTE', 'REUTILIZADO', 'DESCARTADO'],
    EM_DESMONTE: ['RECICLADO', 'REUTILIZADO', 'DESCARTADO'],
    REUTILIZADO: [], RECICLADO: [], DESCARTADO: [],
};
class PapelUsuario {
    pode(p) {
        if (p === 'sessao')
            return true;
        if (!this.conj)
            this.conj = new Set(this.permissoes());
        return this.conj.has(p);
    }
    static porNome(n) {
        switch (n) {
            case 'ADMIN': return new PapelAdministrador();
            case 'CADASTRO': return new PapelOperadorCadastro();
            case 'ALMOXARIFADO': return new PapelGestorAlmoxarifado();
            case 'AUDITOR': return new PapelAuditor();
        }
    }
}
exports.PapelUsuario = PapelUsuario;
class PapelAdministrador extends PapelUsuario {
    constructor() {
        super(...arguments);
        this.nome = 'ADMIN';
        this.rotulo = 'Administrador do sistema';
    }
    permissoes() {
        return ['usuario:gerir', 'param:gerir', 'param:ler', 'org:ler', 'org:escrever', 'lote:ler', 'lote:escrever',
            'equip:ler', 'equip:escrever', 'relatorio:ler', 'journal:ler'];
    }
}
exports.PapelAdministrador = PapelAdministrador;
class PapelOperadorCadastro extends PapelUsuario {
    constructor() {
        super(...arguments);
        this.nome = 'CADASTRO';
        this.rotulo = 'Operador de cadastro';
    }
    permissoes() { return ['org:ler', 'org:escrever', 'lote:ler', 'equip:ler', 'param:ler']; }
}
exports.PapelOperadorCadastro = PapelOperadorCadastro;
class PapelGestorAlmoxarifado extends PapelUsuario {
    constructor() {
        super(...arguments);
        this.nome = 'ALMOXARIFADO';
        this.rotulo = 'Gestor de almoxarifado';
    }
    permissoes() {
        return ['org:ler', 'lote:ler', 'lote:escrever', 'equip:ler', 'equip:escrever', 'param:ler'];
    }
}
exports.PapelGestorAlmoxarifado = PapelGestorAlmoxarifado;
class PapelAuditor extends PapelUsuario {
    constructor() {
        super(...arguments);
        this.nome = 'AUDITOR';
        this.rotulo = 'Auditor (somente leitura)';
    }
    permissoes() { return ['org:ler', 'lote:ler', 'equip:ler', 'param:ler', 'relatorio:ler', 'journal:ler']; }
}
exports.PapelAuditor = PapelAuditor;
// ---------- Equipamentos (herança + polimorfismo + fábrica) ----------
class Equipamento {
    constructor(dados) {
        this.dados = dados;
    }
    coeficienteDepreciacao(params) {
        return params.numero(`depreciacao.${this.tipo}`) ?? this.depreciacaoAnualPadrao();
    }
}
exports.Equipamento = Equipamento;
class Computador extends Equipamento {
    constructor() {
        super(...arguments);
        this.tipo = 'COMPUTADOR';
    }
    depreciacaoAnualPadrao() { return 20; }
    materiaisRecuperaveis() { return ['ouro (placas)', 'cobre', 'alumínio', 'terras raras (HDD)']; }
}
exports.Computador = Computador;
class Servidor extends Equipamento {
    constructor() {
        super(...arguments);
        this.tipo = 'SERVIDOR';
    }
    depreciacaoAnualPadrao() { return 20; }
    materiaisRecuperaveis() { return ['ouro', 'prata', 'cobre', 'paládio', 'terras raras']; }
}
exports.Servidor = Servidor;
class Monitor extends Equipamento {
    constructor() {
        super(...arguments);
        this.tipo = 'MONITOR';
    }
    depreciacaoAnualPadrao() { return 20; }
    materiaisRecuperaveis() { return ['vidro', 'cobre', 'plástico', 'índio (telas)']; }
}
exports.Monitor = Monitor;
class EquipamentoTelecom extends Equipamento {
    constructor() {
        super(...arguments);
        this.tipo = 'TELECOM';
    }
    depreciacaoAnualPadrao() { return 10; }
    materiaisRecuperaveis() { return ['cobre', 'ouro (conectores)', 'alumínio']; }
}
exports.EquipamentoTelecom = EquipamentoTelecom;
class Periferico extends Equipamento {
    constructor() {
        super(...arguments);
        this.tipo = 'PERIFERICO';
    }
    depreciacaoAnualPadrao() { return 20; }
    materiaisRecuperaveis() { return ['plástico', 'cobre']; }
}
exports.Periferico = Periferico;
class EquipamentoGenerico extends Equipamento {
    constructor() {
        super(...arguments);
        this.tipo = 'OUTRO';
    }
    depreciacaoAnualPadrao() { return 10; }
    materiaisRecuperaveis() { return ['metais diversos']; }
}
exports.EquipamentoGenerico = EquipamentoGenerico;
class FabricaEquipamento {
    static criar(dados) {
        switch (dados.tipo) {
            case 'COMPUTADOR': return new Computador(dados);
            case 'SERVIDOR': return new Servidor(dados);
            case 'MONITOR': return new Monitor(dados);
            case 'TELECOM': return new EquipamentoTelecom(dados);
            case 'PERIFERICO': return new Periferico(dados);
            default: return new EquipamentoGenerico(dados);
        }
    }
    /** Código de barras interno: "GC" + sequência (8 dígitos) + dígito verificador módulo 10. */
    static codigoBarras(sequencia) {
        const digitos = pad(sequencia, 8);
        let soma = 0;
        for (let i = 0; i < digitos.length; i++)
            soma += +digitos[i] * (i % 2 === 0 ? 3 : 1);
        return `GC${digitos}${(10 - (soma % 10)) % 10}`;
    }
}
exports.FabricaEquipamento = FabricaEquipamento;
class Validador {
    exigir(valor) {
        const r = this.validar(valor);
        if (!r.ok)
            throw new ErroValidacao(r.erros.join(' '));
    }
    resultado(erros) { return { ok: erros.length === 0, erros }; }
}
exports.Validador = Validador;
/** CNPJ numérico e alfanumérico (a partir de jul/2026); DV módulo 11 com pesos 5..2,9..2 e 6..2,9..2. */
class ValidadorCNPJ extends Validador {
    static normalizar(s) { return s.replace(/[.\/\-\s]/g, '').toUpperCase(); }
    static formatar(s) {
        const n = ValidadorCNPJ.normalizar(s);
        return n.length === 14 ? `${n.slice(0, 2)}.${n.slice(2, 5)}.${n.slice(5, 8)}/${n.slice(8, 12)}-${n.slice(12)}` : s;
    }
    static dv(base, pesos) {
        let soma = 0;
        for (let i = 0; i < pesos.length; i++)
            soma += (base.charCodeAt(i) - 48) * pesos[i];
        const r = soma % 11;
        return r < 2 ? 0 : 11 - r;
    }
    validar(valor) {
        const n = ValidadorCNPJ.normalizar(valor);
        if (!/^[0-9A-Z]{12}\d{2}$/.test(n))
            return this.resultado(['CNPJ com formato inválido (14 posições, DV numéricos).']);
        if (/^(\d)\1{13}$/.test(n))
            return this.resultado(['CNPJ inválido (dígitos repetidos).']);
        const d1 = ValidadorCNPJ.dv(n.slice(0, 12), [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
        const d2 = ValidadorCNPJ.dv(n.slice(0, 12) + d1, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
        if (d1 !== +n[12] || d2 !== +n[13])
            return this.resultado(['CNPJ inválido (dígitos verificadores não conferem).']);
        return this.resultado([]);
    }
}
exports.ValidadorCNPJ = ValidadorCNPJ;
class ValidadorDataLote extends Validador {
    constructor(relogio = () => new Date()) {
        super();
        this.relogio = relogio;
    }
    validar(valor) {
        const c = parseData(valor);
        if (!c)
            return this.resultado(['Data inválida. Use AAAA-MM-DD ou DD/MM/AAAA.']);
        const dif = diaOrdinal(hojeCivil(this.relogio())) - diaOrdinal(c);
        if (dif < 0)
            return this.resultado(['Data de entrada futura não é permitida.']);
        if (dif > exports.LOTE_MAX_DIAS_RETROATIVO) {
            return this.resultado([`Data de entrada anterior a mais de ${exports.LOTE_MAX_DIAS_RETROATIVO} dias não é permitida.`]);
        }
        return this.resultado([]);
    }
}
exports.ValidadorDataLote = ValidadorDataLote;
class ValidadorTransicaoStatus extends Validador {
    validar(v) {
        if (!exports.TRANSICOES[v.atual].includes(v.para)) {
            const ok = exports.TRANSICOES[v.atual].join(', ') || '(estado final)';
            return this.resultado([`Transição ${v.atual} → ${v.para} não permitida. Próximos status válidos: ${ok}.`]);
        }
        if (v.para === 'EM_DESMONTE' && (v.atual !== 'TRIADO' || !v.triagemCompleta)) {
            return this.resultado(['O equipamento só pode ir para EM_DESMONTE após triagem completa.']);
        }
        return this.resultado([]);
    }
}
exports.ValidadorTransicaoStatus = ValidadorTransicaoStatus;
class ValidadorMudancaEstado extends Validador {
    validar(v) {
        const queda = exports.PESO_ESTADO[v.de] - exports.PESO_ESTADO[v.para];
        if (queda >= 2 && (v.justificativa ?? '').trim().length < 10) {
            return this.resultado([`Queda de ${queda} categorias (${v.de} → ${v.para}) exige --justificativa (mín. 10 caracteres).`]);
        }
        return this.resultado([]);
    }
}
exports.ValidadorMudancaEstado = ValidadorMudancaEstado;
class ValidadorSenha extends Validador {
    validar({ senha, usuario }) {
        const e = [];
        if (senha.length < 10)
            e.push('mínimo de 10 caracteres');
        if (!/[a-z]/.test(senha))
            e.push('uma letra minúscula');
        if (!/[A-Z]/.test(senha))
            e.push('uma letra maiúscula');
        if (!/\d/.test(senha))
            e.push('um dígito');
        if (!/[^A-Za-z0-9]/.test(senha))
            e.push('um símbolo');
        if (usuario && senha.toLowerCase().includes(usuario.toLowerCase()))
            e.push('não conter o nome de usuário');
        return this.resultado(e.length ? [`Senha fraca. Requisitos: ${e.join('; ')}.`] : []);
    }
}
exports.ValidadorSenha = ValidadorSenha;
class Colecao {
    constructor(nome, arq) {
        this.nome = nome;
        this.arq = arq;
        this.itens = new Map();
    }
    get arquivo() { return `${this.nome}.dat`; }
    carregar() { this.itens = new Map(this.arq.lerJSON(this.arquivo, []).map((r) => [r.id, r])); }
    salvar() { this.arq.gravarJSON(this.arquivo, [...this.itens.values()]); }
    obter(id) { const r = this.itens.get(id); return r ? clonar(r) : undefined; }
    tem(id) { return this.itens.has(id); }
    todos() { return [...this.itens.values()].map(clonar); }
    filtrar(fn) { return this.todos().filter(fn); }
    upsert(r) { this.itens.set(r.id, clonar(r)); }
}
exports.Colecao = Colecao;
/**
 * Journal imutável: cada linha é cifrada (AES-256-GCM) e encadeada por hash (SHA-256) à anterior.
 * Remover/alterar qualquer linha quebra a cadeia ou a autenticação GCM.
 */
class Journal {
    constructor(dir, cripto, relogio = () => new Date(), maxBytes = exports.JOURNAL_MAX_BYTES, retencaoDias = exports.JOURNAL_RETENCAO_DIAS) {
        this.dir = dir;
        this.cripto = cripto;
        this.relogio = relogio;
        this.maxBytes = maxBytes;
        this.retencaoDias = retencaoDias;
        this.ultimoHash = 'GENESIS';
        this.seq = 0;
        this.arquivo = path.join(dir, 'journal.log');
    }
    rotacionados() {
        return fs.readdirSync(this.dir).filter((f) => /^journal\..+\.log$/.test(f)).sort().map((f) => path.join(this.dir, f));
    }
    lerArquivo(arq) {
        if (!fs.existsSync(arq))
            return [];
        const texto = fs.readFileSync(arq, 'utf8');
        const linhas = texto.split('\n');
        const out = [];
        linhas.forEach((l, i) => {
            if (!l)
                return;
            try {
                out.push(JSON.parse(this.cripto.decifrar(Buffer.from(l, 'base64'), 'journal').toString('utf8')));
            }
            catch {
                throw new ErroIntegridade(`Journal corrompido em ${path.basename(arq)} (linha ${i + 1}).`);
            }
        });
        return out;
    }
    inicializar() {
        // Remove cauda incompleta (queda de energia no meio da escrita da última linha).
        if (fs.existsSync(this.arquivo)) {
            const t = fs.readFileSync(this.arquivo, 'utf8');
            if (t.length > 0 && !t.endsWith('\n'))
                fs.truncateSync(this.arquivo, t.lastIndexOf('\n') + 1);
        }
        const todas = this.lerTodas();
        const ult = todas[todas.length - 1];
        this.seq = ult?.seq ?? 0;
        this.ultimoHash = ult?.hash ?? 'GENESIS';
        this.purgarAntigos();
    }
    ultima() { const t = this.lerTodas(); return t[t.length - 1]; }
    lerTodas() {
        return [...this.rotacionados(), this.arquivo].flatMap((a) => this.lerArquivo(a));
    }
    append(p) {
        this.rotacionarSePreciso();
        const corpo = { seq: this.seq + 1, ts: this.relogio().toISOString(), ...p, prev: this.ultimoHash };
        const hash = this.cripto.sha256Hex(`${this.ultimoHash}|${JSON.stringify(corpo)}`);
        const entrada = { ...corpo, hash };
        const linha = Buffer.from(this.cripto.cifrar(JSON.stringify(entrada), 'journal').toString('base64') + '\n', 'utf8');
        const fd = fs.openSync(this.arquivo, 'a', 0o600);
        try {
            fs.writeSync(fd, linha, 0, linha.length);
            fs.fsyncSync(fd);
        }
        finally {
            fs.closeSync(fd);
        }
        this.seq = entrada.seq;
        this.ultimoHash = hash;
        return entrada;
    }
    rotacionarSePreciso() {
        if (fs.existsSync(this.arquivo) && fs.statSync(this.arquivo).size >= this.maxBytes) {
            const carimbo = this.relogio().toISOString().replace(/[:.]/g, '-');
            fs.renameSync(this.arquivo, path.join(this.dir, `journal.${carimbo}.log`));
        }
    }
    /** Retenção: arquivos rotacionados só são removidos após 180 dias (mínimo) da última gravação. */
    purgarAntigos() {
        const limite = this.relogio().getTime() - this.retencaoDias * 86400000;
        let n = 0;
        for (const f of this.rotacionados()) {
            if (fs.statSync(f).mtimeMs < limite) {
                fs.unlinkSync(f);
                n++;
            }
        }
        return n;
    }
    verificar() {
        const erros = [];
        let todas = [];
        try {
            todas = this.lerTodas();
        }
        catch (e) {
            return { ok: false, total: 0, erros: [e.message] };
        }
        let esperado = todas[0]?.prev ?? 'GENESIS';
        let seqEsperada = (todas[0]?.seq ?? 1);
        for (const e of todas) {
            const { hash, ...corpo } = e;
            if (e.seq !== seqEsperada)
                erros.push(`Sequência quebrada: esperado #${seqEsperada}, encontrado #${e.seq}.`);
            if (e.prev !== esperado)
                erros.push(`Encadeamento quebrado na entrada #${e.seq}.`);
            if (this.cripto.sha256Hex(`${e.prev}|${JSON.stringify(corpo)}`) !== hash)
                erros.push(`Hash inválido na entrada #${e.seq}.`);
            esperado = hash;
            seqEsperada = e.seq + 1;
        }
        return { ok: erros.length === 0, total: todas.length, erros };
    }
}
exports.Journal = Journal;
/** Banco de dados em arquivos: toda alteração passa por executar() (write-ahead no journal). */
class Banco {
    constructor(dir, cripto, relogio = () => new Date()) {
        this.dir = dir;
        this.cripto = cripto;
        this.recuperouTransacao = false;
        this.arq = new ArmazenamentoCifrado(dir, cripto);
        this.credenciais = new Colecao('credenciais', this.arq);
        this.organizacoes = new Colecao('organizacoes', this.arq);
        this.lotes = new Colecao('lotes', this.arq);
        this.equipamentos = new Colecao('equipamentos', this.arq);
        this.movimentacoes = new Colecao('movimentacoes', this.arq);
        this.parametros = new Colecao('parametros', this.arq);
        this.journal = new Journal(dir, cripto, relogio);
    }
    todas() {
        return [this.credenciais, this.organizacoes, this.lotes, this.equipamentos, this.movimentacoes, this.parametros];
    }
    porNome(n) { return this.todas().find((c) => c.nome === n); }
    abrir() {
        for (const f of fs.readdirSync(this.dir))
            if (f.endsWith('.tmp')) {
                try {
                    fs.unlinkSync(path.join(this.dir, f));
                }
                catch { /* ignora */ }
            }
        this.todas().forEach((c) => c.carregar());
        this.journal.inicializar();
        this.recuperar();
    }
    /** Recuperação: uma INTENT sem COMMIT/ABORT (queda durante a gravação) é reaplicada de forma idempotente. */
    recuperar() {
        const ult = this.journal.ultima();
        if (ult && ult.tipo === 'INTENT' && ult.mutacoes && ult.tx) {
            this.aplicar(ult.mutacoes);
            this.journal.append({ tipo: 'COMMIT', tx: ult.tx, operacao: ult.operacao, ator: 'sistema', resumo: 'RECUPERADO após interrupção' });
            this.recuperouTransacao = true;
        }
    }
    aplicar(mutacoes) {
        const tocadas = new Set();
        for (const m of mutacoes) {
            const c = this.porNome(m.colecao);
            c.upsert(m.registro);
            tocadas.add(c);
        }
        tocadas.forEach((c) => c.salvar());
    }
    executar(operacao, ator, resumo, mutacoes) {
        const tx = crypto.randomUUID();
        this.journal.append({ tipo: 'INTENT', tx, operacao, ator, resumo, mutacoes: clonar(mutacoes) });
        try {
            this.aplicar(mutacoes);
        }
        catch (e) {
            this.todas().forEach((c) => { try {
                c.carregar();
            }
            catch { /* ignora */ } });
            throw new ErroSistema(`Falha ao gravar dados (${e.message}). A operação será reconciliada pelo journal na próxima inicialização.`);
        }
        this.journal.append({ tipo: 'COMMIT', tx, operacao, ator });
    }
    evento(operacao, ator, resumo) {
        this.journal.append({ tipo: 'EVENTO', operacao, ator, resumo });
    }
}
exports.Banco = Banco;
// ============================================================================
// 8. SERVIÇOS: PARÂMETROS, AUTENTICAÇÃO, DOMÍNIO
// ============================================================================
exports.PARAMETROS_PADRAO = {
    'aliquota.icms': '18', 'aliquota.iss': '5', 'aliquota.pis_cofins': '9.25',
    'depreciacao.COMPUTADOR': '20', 'depreciacao.SERVIDOR': '20', 'depreciacao.MONITOR': '20',
    'depreciacao.TELECOM': '10', 'depreciacao.PERIFERICO': '20', 'depreciacao.OUTRO': '10',
};
class ServicoParametros {
    constructor(banco, relogio = () => new Date()) {
        this.banco = banco;
        this.relogio = relogio;
    }
    obter(chave) { return this.banco.parametros.obter(chave)?.valor ?? exports.PARAMETROS_PADRAO[chave]; }
    numero(chave) { const v = this.obter(chave); return v === undefined ? undefined : Number(v); }
    listar() {
        const mapa = new Map();
        for (const [id, valor] of Object.entries(exports.PARAMETROS_PADRAO))
            mapa.set(id, { id, valor, atualizadoEm: '-', atualizadoPor: '(padrão)' });
        this.banco.parametros.todos().forEach((p) => mapa.set(p.id, p));
        return [...mapa.values()].sort((a, b) => a.id.localeCompare(b.id));
    }
    definir(ator, chave, valor) {
        if (!/^(aliquota|depreciacao)\.[A-Za-z0-9_]{1,40}$/.test(chave)) {
            throw new ErroValidacao('Chave inválida. Use "aliquota.<nome>" ou "depreciacao.<TIPO>".');
        }
        const n = Number(valor.replace(',', '.'));
        if (!Number.isFinite(n) || n < 0 || n > 100)
            throw new ErroValidacao('Valor inválido: informe um percentual entre 0 e 100.');
        const p = { id: chave, valor: String(n), atualizadoEm: this.relogio().toISOString(), atualizadoPor: ator };
        this.banco.executar('PARAM_DEFINIR', ator, `${chave} = ${n}`, [{ colecao: 'parametros', registro: p }]);
        return p;
    }
}
exports.ServicoParametros = ServicoParametros;
class Sessao {
    constructor(usuario, papel, timeoutMs = exports.SESSAO_TIMEOUT_MS, relogio = () => Date.now()) {
        this.usuario = usuario;
        this.papel = papel;
        this.timeoutMs = timeoutMs;
        this.relogio = relogio;
        this.inicio = this.ultimo = relogio();
    }
    expirada() { return this.relogio() - this.ultimo > this.timeoutMs; }
    renovar() { this.ultimo = this.relogio(); }
    get minutosInativa() { return Math.floor((this.relogio() - this.ultimo) / 60000); }
}
exports.Sessao = Sessao;
class ServicoAutenticacao {
    constructor(banco, relogio = () => Date.now()) {
        this.banco = banco;
        this.relogio = relogio;
        this.falhas = new Map();
    }
    /** Hash de senha: PBKDF2-HMAC-SHA256 (SHA-256 com salt aleatório e 210.000 iterações). */
    static derivar(senha, salt, iter = exports.PBKDF2_ITERACOES) {
        return crypto.pbkdf2Sync(senha, salt, iter, 32, 'sha256').toString('hex');
    }
    static novaCredencial(nome, papel, senha, agora = new Date()) {
        const salt = crypto.randomBytes(16);
        return {
            id: nome, papel, salt: salt.toString('hex'), hash: ServicoAutenticacao.derivar(senha, salt),
            iteracoes: exports.PBKDF2_ITERACOES, ativo: true, criadoEm: agora.toISOString(), atualizadoEm: agora.toISOString(),
        };
    }
    verificarSenha(c, senha) {
        const calc = Buffer.from(ServicoAutenticacao.derivar(senha, Buffer.from(c.salt, 'hex'), c.iteracoes), 'hex');
        return crypto.timingSafeEqual(calc, Buffer.from(c.hash, 'hex'));
    }
    autenticar(nome, senha) {
        const id = nome.trim().toLowerCase();
        const agora = this.relogio();
        const f = this.falhas.get(id);
        if (f && f.bloqueadoAte > agora) {
            throw new ErroPermissao(`Conta temporariamente bloqueada. Tente novamente em ${Math.ceil((f.bloqueadoAte - agora) / 60000)} min.`);
        }
        const cred = this.banco.credenciais.obter(id);
        // Calcula o hash mesmo quando o usuário não existe (equaliza o tempo de resposta).
        const ok = cred
            ? this.verificarSenha(cred, senha)
            : (ServicoAutenticacao.derivar(senha, Buffer.alloc(16)), false);
        if (!cred || !ok || !cred.ativo) {
            const reg = f ?? { n: 0, bloqueadoAte: 0 };
            reg.n++;
            if (reg.n >= exports.MAX_FALHAS_LOGIN) {
                reg.n = 0;
                reg.bloqueadoAte = agora + exports.BLOQUEIO_LOGIN_MS;
            }
            this.falhas.set(id, reg);
            throw new ErroPermissao('Usuário ou senha inválidos.');
        }
        this.falhas.delete(id);
        return cred;
    }
}
exports.ServicoAutenticacao = ServicoAutenticacao;
class ServicoDominio {
    constructor(banco, relogio = () => new Date()) {
        this.banco = banco;
        this.relogio = relogio;
        this.vCnpj = new ValidadorCNPJ();
        this.vTransicao = new ValidadorTransicaoStatus();
        this.vEstado = new ValidadorMudancaEstado();
        this.vData = new ValidadorDataLote(relogio);
    }
    get agoraISO() { return this.relogio().toISOString(); }
    // ---- Organizações e contratos ----
    criarOrganizacao(ator, d) {
        this.vCnpj.exigir(d.cnpj);
        const cnpj = ValidadorCNPJ.normalizar(d.cnpj);
        if (this.banco.organizacoes.filtrar((o) => o.cnpj === cnpj).length > 0) {
            throw new ErroNegocio(`CNPJ ${ValidadorCNPJ.formatar(cnpj)} já cadastrado.`);
        }
        const nome = d.nome.trim();
        if (nome.length < 3 || nome.length > 120)
            throw new ErroValidacao('Nome da organização deve ter entre 3 e 120 caracteres.');
        const org = {
            id: proximoId(this.banco.organizacoes, 'BR', 3), cnpj, nome, tipo: normalizarEnum(d.tipo, exports.TIPOS_ORG, 'Tipo'),
            contratos: [], ativa: true, criadoEm: this.agoraISO, criadoPor: ator,
        };
        this.banco.executar('ORG_CRIAR', ator, `Organização ${org.id} (${ValidadorCNPJ.formatar(cnpj)}) cadastrada`, [{ colecao: 'organizacoes', registro: org }]);
        return org;
    }
    obterOrganizacao(codigo) {
        const o = this.banco.organizacoes.obter(codigo.trim().toUpperCase());
        if (!o)
            throw new ErroNaoEncontrado(`Organização "${codigo}" não encontrada.`);
        return o;
    }
    adicionarContrato(ator, codigo, d) {
        const org = this.obterOrganizacao(codigo);
        const ini = parseData(d.inicio), fim = parseData(d.fim);
        if (!ini || !fim)
            throw new ErroValidacao('Datas inválidas. Use AAAA-MM-DD ou DD/MM/AAAA.');
        if (diaOrdinal(fim) < diaOrdinal(ini))
            throw new ErroValidacao('A data final do contrato é anterior à inicial.');
        const prazo = Number(d.prazoDias);
        if (!Number.isInteger(prazo) || prazo < 1 || prazo > 3650)
            throw new ErroValidacao('--prazo-dias deve ser inteiro entre 1 e 3650.');
        const contrato = {
            numero: `${org.id}-C${pad(org.contratos.length + 1, 2)}`, inicio: formatarISO(ini), fim: formatarISO(fim),
            prazoArmazenamentoDias: prazo, descricao: (d.descricao ?? '').trim(), criadoEm: this.agoraISO,
        };
        org.contratos.push(contrato);
        this.banco.executar('CONTRATO_CRIAR', ator, `Contrato ${contrato.numero} para ${org.id}`, [{ colecao: 'organizacoes', registro: org }]);
        return contrato;
    }
    // ---- Lotes ----
    criarLote(ator, d) {
        const org = this.obterOrganizacao(d.org);
        if (!org.ativa)
            throw new ErroNegocio(`Organização ${org.id} está inativa.`);
        const dataTxt = d.data ?? formatarISO(hojeCivil(this.relogio()));
        this.vData.exigir(dataTxt);
        const data = formatarISO(parseData(dataTxt));
        if (!/^\d{1,9}$/.test(d.nf.trim()))
            throw new ErroValidacao('Nota fiscal inválida: use apenas dígitos (até 9).');
        const nf = d.nf.trim();
        const transp = d.transp.trim();
        if (transp.length < 2 || transp.length > 60)
            throw new ErroValidacao('Transportadora deve ter entre 2 e 60 caracteres.');
        const vigente = org.contratos.some((c) => c.inicio <= data && data <= c.fim);
        if (!vigente)
            throw new ErroNegocio(`Organização ${org.id} não possui contrato de coleta vigente em ${data}.`);
        if (this.banco.lotes.filtrar((l) => l.orgId === org.id && l.notaFiscal === nf).length > 0) {
            throw new ErroNegocio(`Já existe lote da organização ${org.id} com a nota fiscal ${nf}.`);
        }
        const lote = {
            id: proximoId(this.banco.lotes, 'LT-', 6), orgId: org.id, notaFiscal: nf, transportadora: transp,
            dataEntrada: data, criadoEm: this.agoraISO, criadoPor: ator,
        };
        this.banco.executar('LOTE_CRIAR', ator, `Lote ${lote.id} (${org.id}, NF ${nf}, ${transp}) criado`, [{ colecao: 'lotes', registro: lote }]);
        return lote;
    }
    obterLote(id) {
        const l = this.banco.lotes.obter(id.trim().toUpperCase());
        if (!l)
            throw new ErroNaoEncontrado(`Lote "${id}" não encontrado.`);
        return l;
    }
    // ---- Equipamentos ----
    obterEquipamento(id) {
        const e = this.banco.equipamentos.obter(id.trim().toUpperCase());
        if (!e)
            throw new ErroNaoEncontrado(`Equipamento "${id}" não encontrado.`);
        return e;
    }
    movimentacao(eq, ator, tipo, statusDe, estadoDe, extra = {}) {
        return {
            id: proximoId(this.banco.movimentacoes, 'MV-', 6), equipId: eq.id, ts: this.agoraISO, ator, tipo,
            statusDe, statusPara: eq.status, estadoDe, estadoPara: eq.estado, ...extra,
        };
    }
    registrarEquipamento(ator, d) {
        const lote = this.obterLote(d.lote);
        const descricao = d.descricao.trim();
        if (descricao.length < 3 || descricao.length > 120)
            throw new ErroValidacao('Descrição deve ter entre 3 e 120 caracteres.');
        let serie;
        if (d.serie) {
            serie = d.serie.trim().toUpperCase();
            if (!/^[A-Z0-9._-]{3,40}$/.test(serie))
                throw new ErroValidacao('Número de série inválido (3-40 caracteres: letras, dígitos, . _ -).');
            if (this.banco.equipamentos.filtrar((e) => e.serie === serie).length > 0)
                throw new ErroNegocio(`Número de série ${serie} já registrado.`);
        }
        const id = proximoId(this.banco.equipamentos, 'EQ-', 6);
        const eq = {
            id, loteId: lote.id, tipo: normalizarEnum(d.tipo, exports.TIPOS_EQUIP, 'Tipo'), descricao, serie,
            codigoBarras: FabricaEquipamento.codigoBarras(parseInt(id.slice(3), 10)),
            estado: d.estado ? normalizarEnum(d.estado, exports.ESTADOS, 'Estado') : 'BOM', status: 'RECEBIDO',
            criadoEm: this.agoraISO, criadoPor: ator,
        };
        const mv = this.movimentacao(eq, ator, 'REGISTRO', null, null);
        this.banco.executar('EQUIP_REGISTRAR', ator, `Equipamento ${id} (${eq.tipo}) registrado no lote ${lote.id}`, [{ colecao: 'equipamentos', registro: eq }, { colecao: 'movimentacoes', registro: mv }]);
        return eq;
    }
    moverStatus(ator, id, para, observacao) {
        const eq = this.obterEquipamento(id);
        const destino = normalizarEnum(para, exports.STATUS, 'Status');
        if (destino === 'TRIADO')
            throw new ErroNegocio('Para marcar como TRIADO use "equip triar" (a triagem completa é obrigatória).');
        this.vTransicao.exigir({ atual: eq.status, para: destino, triagemCompleta: !!eq.triagem });
        const antes = eq.status;
        eq.status = destino;
        const mv = this.movimentacao(eq, ator, 'STATUS', antes, eq.estado, { observacao });
        this.banco.executar('EQUIP_STATUS', ator, `${eq.id}: ${antes} → ${destino}`, [{ colecao: 'equipamentos', registro: eq }, { colecao: 'movimentacoes', registro: mv }]);
        return eq;
    }
    triar(ator, id, d) {
        const eq = this.obterEquipamento(id);
        if (eq.status !== 'EM_TRIAGEM')
            throw new ErroNegocio(`Equipamento ${eq.id} está ${eq.status}; a triagem exige status EM_TRIAGEM.`);
        const novoEstado = normalizarEnum(d.estado, exports.ESTADOS, 'Estado');
        const classe = normalizarEnum(d.classe, exports.CLASSES_TRIAGEM, 'Classe');
        this.vEstado.exigir({ de: eq.estado, para: novoEstado, justificativa: d.justificativa });
        const estadoAntes = eq.estado;
        eq.estado = novoEstado;
        eq.status = 'TRIADO';
        eq.triagem = { estado: novoEstado, classe, responsavel: ator, data: this.agoraISO, observacao: d.observacao };
        const mv = this.movimentacao(eq, ator, 'TRIAGEM', 'EM_TRIAGEM', estadoAntes, { justificativa: d.justificativa, observacao: d.observacao });
        this.banco.executar('EQUIP_TRIAR', ator, `${eq.id} triado: ${classe}, estado ${estadoAntes} → ${novoEstado}`, [{ colecao: 'equipamentos', registro: eq }, { colecao: 'movimentacoes', registro: mv }]);
        return eq;
    }
    alterarEstado(ator, id, novo, justificativa) {
        const eq = this.obterEquipamento(id);
        if (exports.TRANSICOES[eq.status].length === 0)
            throw new ErroNegocio(`Equipamento ${eq.id} está em status final (${eq.status}).`);
        const alvo = normalizarEnum(novo, exports.ESTADOS, 'Estado');
        if (alvo === eq.estado)
            throw new ErroNegocio(`Equipamento ${eq.id} já está no estado ${alvo}.`);
        this.vEstado.exigir({ de: eq.estado, para: alvo, justificativa });
        const antes = eq.estado;
        eq.estado = alvo;
        const mv = this.movimentacao(eq, ator, 'ESTADO', eq.status, antes, { justificativa });
        this.banco.executar('EQUIP_ESTADO', ator, `${eq.id}: estado ${antes} → ${alvo}`, [{ colecao: 'equipamentos', registro: eq }, { colecao: 'movimentacoes', registro: mv }]);
        return eq;
    }
    rastrear(id) {
        const eq = this.obterEquipamento(id);
        return this.banco.movimentacoes.filtrar((m) => m.equipId === eq.id).sort((a, b) => a.id.localeCompare(b.id));
    }
}
exports.ServicoDominio = ServicoDominio;
// ============================================================================
// 9. INTERPRETAÇÃO DE COMANDOS
// ============================================================================
function tokenizar(linha) {
    const out = [];
    let atual = '', aspas = null, tem = false;
    for (const ch of linha) {
        if (aspas) {
            if (ch === aspas)
                aspas = null;
            else
                atual += ch;
        }
        else if (ch === '"' || ch === "'") {
            aspas = ch;
            tem = true;
        }
        else if (/\s/.test(ch)) {
            if (tem) {
                out.push(atual);
                atual = '';
                tem = false;
            }
        }
        else {
            atual += ch;
            tem = true;
        }
    }
    if (aspas)
        throw new ErroValidacao('Aspas não fechadas no comando.');
    if (tem)
        out.push(atual);
    return out;
}
class ArgsComando {
    constructor(posicionais, flags) {
        this.posicionais = posicionais;
        this.flags = flags;
    }
    nomesFlags() { return [...this.flags.keys()]; }
    opcional(n) { const v = this.flags.get(n); return v === '' ? undefined : v; }
    exigir(n) {
        const v = this.flags.get(n);
        if (v === undefined || v === '')
            throw new ErroValidacao(`Parâmetro obrigatório ausente: --${n}`);
        return v;
    }
    posicional(i, nome) {
        const v = this.posicionais[i];
        if (v === undefined)
            throw new ErroValidacao(`Argumento obrigatório ausente: <${nome}>`);
        return v;
    }
}
exports.ArgsComando = ArgsComando;
function analisarArgumentos(tokens) {
    const pos = [];
    const flags = new Map();
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        if (t.startsWith('--') && t.length > 2) {
            let nome = t.slice(2), valor = '';
            const eq = nome.indexOf('=');
            if (eq >= 0) {
                valor = nome.slice(eq + 1);
                nome = nome.slice(0, eq);
            }
            else if (i + 1 < tokens.length && !tokens[i + 1].startsWith('--'))
                valor = tokens[++i];
            if (flags.has(nome))
                throw new ErroValidacao(`Parâmetro --${nome} informado mais de uma vez.`);
            flags.set(nome, valor);
        }
        else
            pos.push(t);
    }
    return new ArgsComando(pos, flags);
}
const ALIAS_RECURSO = {
    equipamento: 'equip', organizacao: 'org', organizacoes: 'org', lotes: 'lote', usuarios: 'usuario',
    parametro: 'param', parametros: 'param', relatorios: 'relatorio', help: 'ajuda', exit: 'sair', quit: 'sair',
};
const ALIAS_PAPEL = {
    ADMINISTRADOR: 'ADMIN', OPERADOR_CADASTRO: 'CADASTRO', GESTOR_ALMOXARIFADO: 'ALMOXARIFADO',
};
// ============================================================================
// 10. TERMINAL (readline: autocompletar, histórico, senha oculta)
// ============================================================================
class Terminal {
    constructor(completer) {
        this.fila = [];
        this.esperando = null;
        this.fechado = false;
        this.mudo = false;
        const saidaMutavel = new stream_1.Writable({
            write: (chunk, enc, cb) => { if (!this.mudo)
                process.stdout.write(chunk, enc); cb(); },
        });
        Object.defineProperty(saidaMutavel, 'columns', { get: () => process.stdout.columns });
        this.rl = readline.createInterface({
            input: process.stdin, output: saidaMutavel, terminal: !!process.stdin.isTTY,
            completer, historySize: HISTORICO_MAX,
        });
        this.rl.on('line', (l) => {
            if (this.esperando) {
                const r = this.esperando;
                this.esperando = null;
                r(l);
            }
            else
                this.fila.push(l);
        });
        this.rl.on('close', () => {
            this.fechado = true;
            if (this.esperando) {
                const r = this.esperando;
                this.esperando = null;
                r(null);
            }
        });
    }
    get hist() { const h = this.rl.history; return Array.isArray(h) ? h : undefined; }
    historico() { return [...(this.hist ?? [])]; }
    carregarHistorico(lista) { const h = this.hist; if (h) {
        h.length = 0;
        h.push(...lista.slice(0, HISTORICO_MAX));
    } }
    ler(prompt, mudo = false) {
        if (this.fila.length > 0) {
            process.stdout.write(mudo ? `${prompt}\n` : prompt);
            const l = this.fila.shift();
            if (!mudo)
                process.stdout.write(`${l}\n`);
            return Promise.resolve(l);
        }
        if (this.fechado)
            return Promise.resolve(null);
        this.mudo = mudo;
        if (mudo) {
            process.stdout.write(prompt);
            this.rl.setPrompt('');
        }
        else
            this.rl.setPrompt(prompt);
        this.rl.prompt();
        return new Promise((res) => {
            this.esperando = (l) => {
                this.mudo = false;
                if (mudo) {
                    process.stdout.write('\n');
                    const h = this.hist; // a senha nunca pode ficar no histórico
                    if (h && l !== null && h[0] === l)
                        h.shift();
                }
                res(l);
            };
        });
    }
    fechar() { this.rl.close(); }
}
exports.Terminal = Terminal;
class TravaInstancia {
    constructor(caminho) {
        this.caminho = caminho;
    }
    adquirir() {
        try {
            const fd = fs.openSync(this.caminho, 'wx', 0o600);
            fs.writeSync(fd, String(process.pid));
            fs.closeSync(fd);
        }
        catch (e) {
            if (e.code !== 'EEXIST')
                throw e;
            const pid = parseInt(fs.readFileSync(this.caminho, 'utf8'), 10);
            let vivo = false;
            if (pid) {
                try {
                    process.kill(pid, 0);
                    vivo = true;
                }
                catch (err) {
                    vivo = err.code === 'EPERM';
                }
            }
            if (vivo)
                throw new ErroNegocio(`Outra instância do greencode (PID ${pid}) já usa este diretório de dados.`);
            fs.unlinkSync(this.caminho);
            this.adquirir();
        }
    }
    liberar() { try {
        fs.unlinkSync(this.caminho);
    }
    catch { /* ignora */ } }
}
function diretorioPadrao() {
    if (process.env.GREENCODE_HOME)
        return process.env.GREENCODE_HOME;
    if (process.platform === 'win32')
        return path.join(process.env.APPDATA ?? path.join(os.homedir(), 'AppData', 'Roaming'), 'greencode');
    return path.join(process.env.XDG_DATA_HOME ?? path.join(os.homedir(), '.local', 'share'), 'greencode');
}
// ============================================================================
// 12. APLICAÇÃO (CLI)
// ============================================================================
class Aplicacao {
    constructor(dir) {
        this.dir = dir;
        this.saida = new Saida();
        this.sessao = null;
        this.encerrar = false;
        this.arquivoMestre = path.join(dir, 'master.json');
        this.trava = new TravaInstancia(path.join(dir, 'greencode.lock'));
        this.comandos = this.construirComandos();
    }
    get ator() { return this.sessao.usuario; }
    // ---------------- Inicialização ----------------
    static async principal(argv) {
        if (argv.includes('--versao') || argv.includes('-v')) {
            console.log(`greencode ${exports.VERSAO}`);
            return 0;
        }
        if (argv.includes('--ajuda') || argv.includes('-h')) {
            console.log('Uso: greencode [--dir <diretório de dados>]\nVariável: GREENCODE_HOME define o diretório de dados.');
            return 0;
        }
        const i = argv.indexOf('--dir');
        const dir = path.resolve(i >= 0 && argv[i + 1] ? argv[i + 1] : diretorioPadrao());
        const app = new Aplicacao(dir);
        try {
            return await app.executar();
        }
        catch (e) {
            if (e instanceof ErroGreencode)
                app.saida.log(e.severidade, e.message);
            else
                app.saida.critico(`Erro inesperado: ${e.message}`);
            return 1;
        }
        finally {
            app.finalizar();
        }
    }
    prepararDiretorio() {
        fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
        if (process.platform !== 'win32') {
            try {
                fs.chmodSync(this.dir, 0o700);
            }
            catch { /* ignora */ }
        }
    }
    carregarMestre() {
        if (!fs.existsSync(this.arquivoMestre))
            return null;
        let cfg;
        try {
            cfg = JSON.parse(fs.readFileSync(this.arquivoMestre, 'utf8'));
        }
        catch {
            throw new ErroIntegridade('Arquivo de configuração mestre ilegível (master.json).');
        }
        if (!cfg.chave || !cfg.verificacao || !cfg.administrador)
            throw new ErroIntegridade('master.json incompleto.');
        this.iniciarServicos(Buffer.from(cfg.chave, 'base64'));
        const teste = this.cripto.decifrar(Buffer.from(cfg.verificacao, 'base64'), 'master').toString('utf8');
        if (teste !== 'GREENCODE-OK')
            throw new ErroIntegridade('Chave mestra não confere com a verificação.');
        return cfg;
    }
    iniciarServicos(chave) {
        this.cripto = new ServicoCriptografia(chave);
        this.banco = new Banco(this.dir, this.cripto);
        this.auth = new ServicoAutenticacao(this.banco);
        this.params = new ServicoParametros(this.banco);
        this.dominio = new ServicoDominio(this.banco);
    }
    async executar() {
        this.prepararDiretorio();
        this.trava.adquirir();
        this.term = new Terminal((l) => this.completar(l));
        this.saida.linha(`greencode ${exports.VERSAO} — logística reversa de eletrônicos`);
        this.saida.linha(`Dados em: ${this.dir}`);
        let cfg = this.carregarMestre();
        if (!cfg)
            cfg = await this.provisionar();
        this.banco.abrir();
        if (this.banco.recuperouTransacao)
            this.saida.aviso('Uma transação interrompida foi recuperada a partir do journal.');
        if (this.banco.credenciais.todos().length === 0) {
            this.saida.aviso('Provisionamento incompleto detectado. Defina a senha do administrador para concluir.');
            await this.concluirProvisionamento(cfg);
        }
        this.timer = setInterval(() => this.verificarExpiracao(true), 15000);
        this.timer.unref();
        await this.laco();
        return 0;
    }
    async provisionar() {
        const existentes = fs.readdirSync(this.dir).filter((f) => f.endsWith('.dat') || f.startsWith('journal'));
        if (existentes.length > 0) {
            throw new ErroIntegridade('master.json ausente, mas existem dados cifrados. Restaure o arquivo mestre do backup; nada foi alterado.');
        }
        this.saida.aviso('Arquivo de configuração mestre não encontrado: iniciando PROVISIONAMENTO INICIAL.');
        const senha = await this.pedirNovaSenha('admin');
        const chave = ServicoCriptografia.gerarChave();
        this.iniciarServicos(chave);
        const agora = new Date().toISOString();
        const cfg = {
            versao: 1, criadoEm: agora, chave: chave.toString('base64'),
            verificacao: this.cripto.cifrar('GREENCODE-OK', 'master').toString('base64'),
            administrador: { id: 'admin', nome: 'Administrador', criadoEm: agora },
        };
        escreverArquivoAtomico(this.arquivoMestre, Buffer.from(JSON.stringify(cfg, null, 2), 'utf8'));
        this.banco.abrir();
        await this.concluirProvisionamento(cfg, senha);
        this.saida.sucesso('Provisionamento concluído. Chave criptográfica gerada e administrador criado.');
        this.saida.aviso('FAÇA BACKUP do arquivo master.json: sem ele os dados cifrados não podem ser recuperados.');
        return cfg;
    }
    async concluirProvisionamento(cfg, senhaJa) {
        const senha = senhaJa ?? (await this.pedirNovaSenha(cfg.administrador.id));
        const admin = ServicoAutenticacao.novaCredencial(cfg.administrador.id, 'ADMIN', senha);
        const muts = [{ colecao: 'credenciais', registro: admin }];
        for (const [id, valor] of Object.entries(exports.PARAMETROS_PADRAO)) {
            muts.push({ colecao: 'parametros', registro: { id, valor, atualizadoEm: new Date().toISOString(), atualizadoPor: 'sistema' } });
        }
        this.banco.executar('PROVISIONAMENTO', 'sistema', `Administrador "${admin.id}" e parâmetros padrão criados`, muts);
    }
    async pedirNovaSenha(usuario) {
        for (let t = 0; t < 3; t++) {
            const s1 = await this.term.ler(`Nova senha para "${usuario}": `, true);
            if (s1 === null)
                throw new ErroNegocio('Entrada encerrada durante a definição da senha.');
            const s2 = await this.term.ler('Confirme a senha: ', true);
            if (s2 === null)
                throw new ErroNegocio('Entrada encerrada durante a definição da senha.');
            if (s1 !== s2) {
                this.saida.erro('As senhas não conferem.');
                continue;
            }
            const r = new ValidadorSenha().validar({ senha: s1, usuario });
            if (!r.ok) {
                this.saida.erro(r.erros.join(' '));
                continue;
            }
            return s1;
        }
        throw new ErroValidacao('Número máximo de tentativas para definir a senha excedido.');
    }
    // ---------------- Sessão ----------------
    async autenticarUsuario() {
        for (let t = 0; t < exports.MAX_FALHAS_LOGIN; t++) {
            const nome = await this.term.ler('Usuário: ');
            if (nome === null)
                return false;
            const senha = await this.term.ler('Senha: ', true);
            if (senha === null)
                return false;
            try {
                const cred = this.auth.autenticar(nome, senha);
                this.sessao = new Sessao(cred.id, PapelUsuario.porNome(cred.papel));
                this.banco.evento('LOGIN_OK', cred.id, 'Autenticação bem-sucedida');
                this.carregarHistoricoUsuario();
                this.saida.sucesso(`Bem-vindo(a), ${cred.id} — ${this.sessao.papel.rotulo}. Digite "ajuda".`);
                return true;
            }
            catch (e) {
                this.banco.evento('LOGIN_FALHA', nome.trim().toLowerCase() || '(vazio)', 'Falha de autenticação');
                this.saida.erro(e.message);
            }
        }
        this.saida.critico('Muitas tentativas de autenticação malsucedidas. Encerrando.');
        return false;
    }
    verificarExpiracao(avisar) {
        if (this.sessao && this.sessao.expirada()) {
            this.encerrarSessao('SESSAO_EXPIRADA', 'Sessão encerrada por inatividade (30 min)');
            if (avisar)
                this.saida.aviso('\nSessão expirada por inatividade. Pressione Enter para autenticar-se novamente.');
            return true;
        }
        return false;
    }
    encerrarSessao(operacao, resumo) {
        if (!this.sessao)
            return;
        this.salvarHistoricoUsuario();
        try {
            this.banco.evento(operacao, this.sessao.usuario, resumo);
        }
        catch { /* ignora */ }
        this.sessao = null;
    }
    carregarHistoricoUsuario() {
        try {
            const mapa = this.banco.arq.lerJSON('historico.dat', {});
            this.term.carregarHistorico(mapa[this.sessao.usuario] ?? []);
        }
        catch {
            this.saida.aviso('Histórico de comandos ilegível; iniciando vazio.');
            this.term.carregarHistorico([]);
        }
    }
    salvarHistoricoUsuario() {
        if (!this.sessao)
            return;
        try {
            let mapa = {};
            try {
                mapa = this.banco.arq.lerJSON('historico.dat', {});
            }
            catch {
                mapa = {};
            }
            mapa[this.sessao.usuario] = this.term.historico().slice(0, HISTORICO_MAX);
            this.banco.arq.gravarJSON('historico.dat', mapa);
        }
        catch { /* histórico é acessório: nunca derruba a aplicação */ }
    }
    async laco() {
        while (!this.encerrar) {
            if (!this.sessao) {
                if (!(await this.autenticarUsuario()))
                    break;
                continue;
            }
            const linha = await this.term.ler(`${this.sessao.usuario}@greencode> `);
            if (linha === null)
                break;
            if (!this.sessao || this.verificarExpiracao(false)) {
                this.saida.aviso('Sessão expirada. Autentique-se novamente.');
                continue;
            }
            this.sessao.renovar();
            try {
                await this.processarLinha(linha);
            }
            catch (e) {
                if (e instanceof ErroGreencode)
                    this.saida.log(e.severidade, `${e.message}`);
                else {
                    this.saida.critico(`Erro inesperado: ${e.message}`);
                    try {
                        this.banco.evento('ERRO_INESPERADO', this.ator, e.message);
                    }
                    catch { /* ignora */ }
                }
            }
        }
        this.encerrarSessao('LOGOUT', 'Encerramento da aplicação');
    }
    finalizar() {
        if (this.timer)
            clearInterval(this.timer);
        try {
            this.term?.fechar();
        }
        catch { /* ignora */ }
        this.trava.liberar();
    }
    // ---------------- Despacho e autocompletar ----------------
    resolver(tokens) {
        const primeiro = ALIAS_RECURSO[tokens[0].toLowerCase()] ?? tokens[0].toLowerCase();
        if (tokens[1] && !tokens[1].startsWith('--')) {
            const c2 = this.comandos.find((c) => c.chave === `${primeiro} ${tokens[1].toLowerCase()}`);
            if (c2)
                return { cmd: c2, restantes: tokens.slice(2) };
        }
        const c1 = this.comandos.find((c) => c.chave === primeiro);
        return { cmd: c1, restantes: tokens.slice(1) };
    }
    visiveis() {
        return this.sessao ? this.comandos.filter((c) => this.sessao.papel.pode(c.permissao)) : [];
    }
    async processarLinha(linha) {
        const tokens = tokenizar(linha);
        if (tokens.length === 0)
            return;
        const { cmd, restantes } = this.resolver(tokens);
        if (!cmd)
            throw new ErroValidacao(`Comando desconhecido: "${tokens.slice(0, 2).join(' ')}". Digite "ajuda".`);
        if (!this.sessao.papel.pode(cmd.permissao)) {
            this.banco.evento('ACESSO_NEGADO', this.ator, `Tentativa de executar "${cmd.chave}" sem permissão (${this.sessao.papel.nome})`);
            throw new ErroPermissao(`Seu papel (${this.sessao.papel.rotulo}) não permite executar "${cmd.chave}".`);
        }
        const args = analisarArgumentos(restantes);
        const invalidas = args.nomesFlags().filter((f) => !cmd.flags.includes(f));
        if (invalidas.length)
            throw new ErroValidacao(`Parâmetro(s) desconhecido(s) para "${cmd.chave}": ${invalidas.map((f) => `--${f}`).join(', ')}. Uso: ${cmd.uso}`);
        await cmd.executar(args);
    }
    completar(linha) {
        const vis = this.visiveis();
        const termina = /\s$/.test(linha);
        const partes = linha.trim() ? linha.trimStart().split(/\s+/) : [];
        const atual = termina ? '' : (partes.pop() ?? '');
        let cand = [];
        if (partes.length === 0) {
            cand = [...new Set(vis.map((c) => c.chave.split(' ')[0]))];
        }
        else if (partes.length === 1 && !atual.startsWith('--')) {
            const r = ALIAS_RECURSO[partes[0].toLowerCase()] ?? partes[0].toLowerCase();
            cand = vis.filter((c) => c.chave.startsWith(`${r} `)).map((c) => c.chave.split(' ')[1]);
        }
        if (atual.startsWith('--') || cand.length === 0) {
            const { cmd } = partes.length ? this.resolver(partes) : { cmd: undefined };
            if (cmd && vis.includes(cmd) && atual.startsWith('--'))
                cand = cmd.flags.map((f) => `--${f}`);
        }
        return [cand.filter((c) => c.startsWith(atual)).sort(), atual];
    }
    // ---------------- Comandos ----------------
    construirComandos() {
        const S = this.saida;
        const dom = () => this.dominio;
        const novoCmd = (chave, uso, descricao, permissao, flags, executar) => ({ chave, uso, descricao, permissao, flags, executar });
        const tabelaEquip = (lista) => S.tabela(['ID', 'CÓD. BARRAS', 'TIPO', 'ESTADO', 'STATUS', 'LOTE', 'DESCRIÇÃO'], lista.map((e) => [e.id, e.codigoBarras, e.tipo, e.estado, e.status, e.loteId, e.descricao]));
        return [
            novoCmd('ajuda', 'ajuda [comando]', 'Lista os comandos disponíveis para o seu papel', 'sessao', [], (a) => {
                const vis = this.visiveis();
                const filtro = a.posicionais[0]?.toLowerCase();
                S.linha('Convenção: <recurso> <ação> [argumentos] [--opção valor]. Use TAB para autocompletar; "↑" para histórico.');
                const lista = filtro ? vis.filter((c) => c.chave.startsWith(ALIAS_RECURSO[filtro] ?? filtro)) : vis;
                if (lista.length === 0)
                    throw new ErroNaoEncontrado(`Nenhum comando disponível para "${filtro}".`);
                const w = Math.max(...lista.map((c) => c.uso.length));
                lista.forEach((c) => S.linha(`  ${c.uso.padEnd(w)}  ${c.descricao}`));
            }),
            novoCmd('quem', 'quem', 'Mostra usuário, papel e tempo de inatividade da sessão', 'sessao', [], () => {
                S.info(`Usuário: ${this.ator} | Papel: ${this.sessao.papel.rotulo} | Inativo há ${this.sessao.minutosInativa} min (limite 30).`);
            }),
            novoCmd('logout', 'logout', 'Encerra a sessão atual', 'sessao', [], () => {
                this.encerrarSessao('LOGOUT', 'Logout voluntário');
                S.sucesso('Sessão encerrada.');
            }),
            novoCmd('sair', 'sair', 'Encerra o greencode', 'sessao', [], () => { this.encerrar = true; }),
            novoCmd('senha alterar', 'senha alterar', 'Altera a sua própria senha', 'sessao', [], async () => {
                const atual = await this.term.ler('Senha atual: ', true);
                if (atual === null)
                    throw new ErroNegocio('Entrada encerrada.');
                const cred = this.banco.credenciais.obter(this.ator);
                if (!this.auth.verificarSenha(cred, atual))
                    throw new ErroPermissao('Senha atual incorreta.');
                const nova = await this.pedirNovaSenha(this.ator);
                const n = ServicoAutenticacao.novaCredencial(cred.id, cred.papel, nova);
                n.criadoEm = cred.criadoEm;
                this.banco.executar('SENHA_ALTERAR', this.ator, 'Senha alterada pelo próprio usuário', [{ colecao: 'credenciais', registro: n }]);
                S.sucesso('Senha alterada.');
            }),
            // ----- Usuários -----
            novoCmd('usuario criar', 'usuario criar --nome <n> --papel <ADMIN|CADASTRO|ALMOXARIFADO|AUDITOR>', 'Cria conta de acesso', 'usuario:gerir', ['nome', 'papel'], async (a) => {
                const nome = a.exigir('nome').trim().toLowerCase();
                if (!/^[a-z][a-z0-9._-]{2,31}$/.test(nome))
                    throw new ErroValidacao('Nome de usuário: 3-32 caracteres (minúsculas, dígitos, . _ -), iniciando por letra.');
                const bruto = a.exigir('papel').trim().toUpperCase().replace(/[\s-]+/g, '_');
                const papel = normalizarEnum(ALIAS_PAPEL[bruto] ?? bruto, exports.NOMES_PAPEIS, 'Papel');
                if (this.banco.credenciais.tem(nome))
                    throw new ErroNegocio(`Usuário "${nome}" já existe.`);
                const senha = await this.pedirNovaSenha(nome);
                const cred = ServicoAutenticacao.novaCredencial(nome, papel, senha);
                this.banco.executar('USUARIO_CRIAR', this.ator, `Usuário ${nome} (${papel}) criado`, [{ colecao: 'credenciais', registro: cred }]);
                S.sucesso(`Usuário "${nome}" criado com o papel ${papel}.`);
            }),
            novoCmd('usuario listar', 'usuario listar', 'Lista as contas de acesso', 'usuario:gerir', [], () => {
                S.tabela(['USUÁRIO', 'PAPEL', 'ATIVO', 'CRIADO EM'], this.banco.credenciais.todos()
                    .map((c) => [c.id, c.papel, c.ativo ? 'sim' : 'não', dataHora(c.criadoEm)]));
            }),
            novoCmd('usuario desativar', 'usuario desativar <nome>', 'Desativa uma conta', 'usuario:gerir', [], (a) => {
                const c = this.banco.credenciais.obter(a.posicional(0, 'nome').toLowerCase());
                if (!c)
                    throw new ErroNaoEncontrado('Usuário não encontrado.');
                if (c.id === this.ator)
                    throw new ErroNegocio('Você não pode desativar a própria conta.');
                if (c.papel === 'ADMIN' && this.banco.credenciais.filtrar((x) => x.papel === 'ADMIN' && x.ativo).length <= 1) {
                    throw new ErroNegocio('Não é possível desativar o último administrador ativo.');
                }
                c.ativo = false;
                c.atualizadoEm = new Date().toISOString();
                this.banco.executar('USUARIO_DESATIVAR', this.ator, `Usuário ${c.id} desativado`, [{ colecao: 'credenciais', registro: c }]);
                S.sucesso(`Usuário "${c.id}" desativado.`);
            }),
            novoCmd('usuario reativar', 'usuario reativar <nome>', 'Reativa uma conta', 'usuario:gerir', [], (a) => {
                const c = this.banco.credenciais.obter(a.posicional(0, 'nome').toLowerCase());
                if (!c)
                    throw new ErroNaoEncontrado('Usuário não encontrado.');
                c.ativo = true;
                c.atualizadoEm = new Date().toISOString();
                this.banco.executar('USUARIO_REATIVAR', this.ator, `Usuário ${c.id} reativado`, [{ colecao: 'credenciais', registro: c }]);
                S.sucesso(`Usuário "${c.id}" reativado.`);
            }),
            novoCmd('usuario redefinir', 'usuario redefinir <nome>', 'Define nova senha para um usuário', 'usuario:gerir', [], async (a) => {
                const c = this.banco.credenciais.obter(a.posicional(0, 'nome').toLowerCase());
                if (!c)
                    throw new ErroNaoEncontrado('Usuário não encontrado.');
                const senha = await this.pedirNovaSenha(c.id);
                const n = ServicoAutenticacao.novaCredencial(c.id, c.papel, senha);
                n.criadoEm = c.criadoEm;
                n.ativo = c.ativo;
                this.banco.executar('USUARIO_REDEFINIR', this.ator, `Senha de ${c.id} redefinida`, [{ colecao: 'credenciais', registro: n }]);
                S.sucesso(`Senha de "${c.id}" redefinida.`);
            }),
            // ----- Parâmetros -----
            novoCmd('param listar', 'param listar', 'Lista alíquotas e coeficientes de depreciação', 'param:ler', [], () => {
                S.tabela(['PARÂMETRO', 'VALOR (%)', 'ATUALIZADO POR'], this.params.listar().map((p) => [p.id, p.valor, p.atualizadoPor]));
            }),
            novoCmd('param definir', 'param definir <chave> <valor>', 'Altera um parâmetro global (ex.: depreciacao.COMPUTADOR 25)', 'param:gerir', [], (a) => {
                const p = this.params.definir(this.ator, a.posicional(0, 'chave'), a.posicional(1, 'valor'));
                S.sucesso(`Parâmetro ${p.id} = ${p.valor}.`);
            }),
            // ----- Organizações -----
            novoCmd('org criar', 'org criar --cnpj <cnpj> --nome <nome> --tipo <tipo>', 'Cadastra organização cliente', 'org:escrever', ['cnpj', 'nome', 'tipo'], (a) => {
                const o = dom().criarOrganizacao(this.ator, { cnpj: a.exigir('cnpj'), nome: a.exigir('nome'), tipo: a.exigir('tipo') });
                S.sucesso(`Organização ${o.id} cadastrada (${ValidadorCNPJ.formatar(o.cnpj)}).`);
            }),
            novoCmd('org listar', 'org listar', 'Lista organizações', 'org:ler', [], () => {
                S.tabela(['CÓDIGO', 'CNPJ', 'NOME', 'TIPO', 'CONTRATOS'], this.banco.organizacoes.todos()
                    .map((o) => [o.id, ValidadorCNPJ.formatar(o.cnpj), o.nome, o.tipo, String(o.contratos.length)]));
            }),
            novoCmd('org ver', 'org ver <código>', 'Detalha uma organização e seus contratos', 'org:ler', [], (a) => {
                const o = dom().obterOrganizacao(a.posicional(0, 'código'));
                S.linha(`  ${o.id} — ${o.nome} [${o.tipo}] CNPJ ${ValidadorCNPJ.formatar(o.cnpj)} | cadastrada por ${o.criadoPor} em ${dataHora(o.criadoEm)}`);
                S.tabela(['CONTRATO', 'INÍCIO', 'FIM', 'PRAZO ARMAZ. (dias)', 'DESCRIÇÃO'], o.contratos.map((c) => [c.numero, c.inicio, c.fim, String(c.prazoArmazenamentoDias), c.descricao]));
                S.linha(`  Lotes: ${this.banco.lotes.filtrar((l) => l.orgId === o.id).length}`);
            }),
            novoCmd('org contrato', 'org contrato <código> --inicio <data> --fim <data> --prazo-dias <n> [--descricao <t>]', 'Registra contrato de coleta', 'org:escrever', ['inicio', 'fim', 'prazo-dias', 'descricao'], (a) => {
                const c = dom().adicionarContrato(this.ator, a.posicional(0, 'código'), {
                    inicio: a.exigir('inicio'), fim: a.exigir('fim'), prazoDias: a.exigir('prazo-dias'), descricao: a.opcional('descricao'),
                });
                S.sucesso(`Contrato ${c.numero} registrado (${c.inicio} a ${c.fim}).`);
            }),
            // ----- Lotes -----
            novoCmd('lote criar', 'lote criar --org <código> --nf <número> --transp <nome> [--data <data>]', 'Registra a chegada de um lote', 'lote:escrever', ['org', 'nf', 'transp', 'data'], (a) => {
                const l = dom().criarLote(this.ator, { org: a.exigir('org'), nf: a.exigir('nf'), transp: a.exigir('transp'), data: a.opcional('data') });
                S.sucesso(`Lote ${l.id} criado para ${l.orgId} (NF ${l.notaFiscal}, ${l.transportadora}, entrada ${l.dataEntrada}).`);
            }),
            novoCmd('lote listar', 'lote listar [--org <código>]', 'Lista lotes', 'lote:ler', ['org'], (a) => {
                const org = a.opcional('org')?.toUpperCase();
                S.tabela(['LOTE', 'ORG', 'NF', 'TRANSPORTADORA', 'ENTRADA', 'EQUIP.'], this.banco.lotes.filtrar((l) => !org || l.orgId === org)
                    .map((l) => [l.id, l.orgId, l.notaFiscal, l.transportadora, l.dataEntrada,
                    String(this.banco.equipamentos.filtrar((e) => e.loteId === l.id).length)]));
            }),
            novoCmd('lote ver', 'lote ver <id>', 'Detalha um lote e seus equipamentos', 'lote:ler', [], (a) => {
                const l = dom().obterLote(a.posicional(0, 'id'));
                S.linha(`  ${l.id} | ${l.orgId} | NF ${l.notaFiscal} | ${l.transportadora} | entrada ${l.dataEntrada} | criado por ${l.criadoPor}`);
                tabelaEquip(this.banco.equipamentos.filtrar((e) => e.loteId === l.id));
            }),
            // ----- Equipamentos -----
            novoCmd('equip registrar', 'equip registrar --lote <id> --tipo <tipo> --desc <texto> [--serie <s>] [--estado <e>]', 'Registra equipamento e aloca código de barras', 'equip:escrever', ['lote', 'tipo', 'desc', 'serie', 'estado'], (a) => {
                const e = dom().registrarEquipamento(this.ator, {
                    lote: a.exigir('lote'), tipo: a.exigir('tipo'), descricao: a.exigir('desc'), serie: a.opcional('serie'), estado: a.opcional('estado'),
                });
                S.sucesso(`Equipamento ${e.id} registrado. Código de barras: ${e.codigoBarras}.`);
            }),
            novoCmd('equip mover', 'equip mover <id> --status <status> [--obs <texto>]', 'Altera o status (RECEBIDO→EM_TRIAGEM→TRIADO→EM_DESMONTE→...)', 'equip:escrever', ['status', 'obs'], (a) => {
                const e = dom().moverStatus(this.ator, a.posicional(0, 'id'), a.exigir('status'), a.opcional('obs'));
                S.sucesso(`${e.id} agora está ${e.status}.`);
            }),
            novoCmd('equip triar', 'equip triar <id> --estado <e> --classe <REUTILIZAVEL|RECICLAVEL|DESCARTE_SEGURO> [--justificativa <t>] [--obs <t>]', 'Conclui a triagem (exige status EM_TRIAGEM)', 'equip:escrever', ['estado', 'classe', 'justificativa', 'obs'], (a) => {
                const e = dom().triar(this.ator, a.posicional(0, 'id'), {
                    estado: a.exigir('estado'), classe: a.exigir('classe'), justificativa: a.opcional('justificativa'), observacao: a.opcional('obs'),
                });
                S.sucesso(`${e.id} triado como ${e.triagem.classe}; estado físico ${e.estado}.`);
            }),
            novoCmd('equip estado', 'equip estado <id> --novo <estado> [--justificativa <t>]', 'Altera o estado físico (queda ≥ 2 categorias exige justificativa)', 'equip:escrever', ['novo', 'justificativa'], (a) => {
                const e = dom().alterarEstado(this.ator, a.posicional(0, 'id'), a.exigir('novo'), a.opcional('justificativa'));
                S.sucesso(`${e.id}: estado físico agora é ${e.estado}.`);
            }),
            novoCmd('equip ver', 'equip ver <id>', 'Detalha um equipamento', 'equip:ler', [], (a) => {
                const r = dom().obterEquipamento(a.posicional(0, 'id'));
                const e = FabricaEquipamento.criar(r);
                S.linha(`  ${r.id} | barras ${r.codigoBarras} | ${r.tipo} | ${r.descricao}${r.serie ? ` | série ${r.serie}` : ''}`);
                S.linha(`  Lote ${r.loteId} | estado ${r.estado} | status ${r.status}`);
                S.linha(`  Depreciação anual: ${e.coeficienteDepreciacao(this.params)}% | materiais recuperáveis: ${e.materiaisRecuperaveis().join(', ')}`);
                if (r.triagem)
                    S.linha(`  Triagem: ${r.triagem.classe} por ${r.triagem.responsavel} em ${dataHora(r.triagem.data)}${r.triagem.observacao ? ` — ${r.triagem.observacao}` : ''}`);
            }),
            novoCmd('equip listar', 'equip listar [--lote <id>] [--status <status>]', 'Lista equipamentos', 'equip:ler', ['lote', 'status'], (a) => {
                const lote = a.opcional('lote')?.toUpperCase();
                const st = a.opcional('status') ? normalizarEnum(a.opcional('status'), exports.STATUS, 'Status') : undefined;
                tabelaEquip(this.banco.equipamentos.filtrar((e) => (!lote || e.loteId === lote) && (!st || e.status === st)));
            }),
            novoCmd('equip rastrear', 'equip rastrear <id>', 'Histórico completo de movimentações do equipamento', 'equip:ler', [], (a) => {
                const lista = dom().rastrear(a.posicional(0, 'id'));
                S.tabela(['MOV.', 'DATA/HORA', 'TIPO', 'STATUS', 'ESTADO', 'ATOR', 'JUSTIFICATIVA/OBS.'], lista.map((m) => [
                    m.id, dataHora(m.ts), m.tipo, `${m.statusDe ?? '-'} → ${m.statusPara}`, `${m.estadoDe ?? '-'} → ${m.estadoPara}`,
                    m.ator, m.justificativa ?? m.observacao ?? '',
                ]));
            }),
            // ----- Relatórios e auditoria -----
            novoCmd('relatorio resumo', 'relatorio resumo', 'Resumo operacional (somente leitura)', 'relatorio:ler', [], () => {
                const eqs = this.banco.equipamentos.todos();
                S.linha(`  Organizações: ${this.banco.organizacoes.todos().length} | Lotes: ${this.banco.lotes.todos().length} | Equipamentos: ${eqs.length}`);
                S.linha('  Por status:');
                S.tabela(['STATUS', 'QTD'], exports.STATUS.map((s) => [s, String(eqs.filter((e) => e.status === s).length)]));
                S.linha('  Por tipo:');
                S.tabela(['TIPO', 'QTD', 'DEPR. ANUAL (%)'], exports.TIPOS_EQUIP.map((t) => [t, String(eqs.filter((e) => e.tipo === t).length),
                    String(this.params.numero(`depreciacao.${t}`) ?? '-')]));
            }),
            novoCmd('relatorio auditoria', 'relatorio auditoria [--dias <n>] [--ator <usuário>]', 'Trilha de auditoria a partir do journal', 'relatorio:ler', ['dias', 'ator'], (a) => {
                const dias = Number(a.opcional('dias') ?? '7');
                if (!Number.isFinite(dias) || dias <= 0)
                    throw new ErroValidacao('--dias deve ser um número positivo.');
                const ator = a.opcional('ator')?.toLowerCase();
                const limite = Date.now() - dias * 86400000;
                const todas = this.banco.journal.lerTodas();
                const commits = new Set(todas.filter((e) => e.tipo === 'COMMIT').map((e) => e.tx));
                const linhas = todas
                    .filter((e) => (e.tipo === 'INTENT' || e.tipo === 'EVENTO') && new Date(e.ts).getTime() >= limite && (!ator || e.ator === ator))
                    .map((e) => [`#${e.seq}`, dataHora(e.ts), e.ator ?? '-', e.operacao ?? e.tipo,
                    e.tipo === 'INTENT' ? (commits.has(e.tx) ? 'efetivada' : 'SEM COMMIT') : 'evento', e.resumo ?? '']);
                S.tabela(['SEQ', 'DATA/HORA', 'ATOR', 'OPERAÇÃO', 'SITUAÇÃO', 'RESUMO'], linhas);
            }),
            novoCmd('journal verificar', 'journal verificar', 'Verifica a integridade e o encadeamento do journal', 'journal:ler', [], () => {
                const r = this.banco.journal.verificar();
                if (r.ok)
                    S.sucesso(`Journal íntegro: ${r.total} entradas verificadas.`);
                else {
                    S.critico('Journal com problemas de integridade:');
                    r.erros.forEach((e) => S.linha(`  - ${e}`));
                }
            }),
        ];
    }
}
exports.Aplicacao = Aplicacao;
// ============================================================================
// 13. PONTO DE ENTRADA
// ============================================================================
if (require.main === module) {
    Aplicacao.principal(process.argv.slice(2)).then((codigo) => process.exit(codigo));
}
