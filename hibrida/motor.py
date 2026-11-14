"""Operações de arquivo com OpenSSL 3.x; comandos executados sem shell."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

OAEP = ['-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
        '-pkeyopt', 'rsa_mgf1_md:sha256']
KDF = ['-pbkdf2', '-iter', '100000', '-md', 'sha256']
PARAMETROS = {'versao': 1, 'cifra': 'aes-256-cbc', 'kdf': 'pbkdf2-sha256',
              'iteracoes': 100000, 'segredo': 'base64-32-bytes',
              'rsa': 'oaep-sha256-mgf1-sha256'}


def sha256(arquivo: Path) -> str:
    h = hashlib.sha256()
    with Path(arquivo).open('rb') as entrada:
        for bloco in iter(lambda: entrada.read(1024 * 1024), b''):
            h.update(bloco)
    return h.hexdigest()


class ErroCriptografia(RuntimeError):
    """Erro de operação ou validação, apresentado pela CLI sem traceback."""


class OpenSSL:
    def __init__(self, executavel: str | None = None, log: Path | None = None):
        candidatos = [executavel, os.environ.get('OPENSSL_EXE'), shutil.which('openssl'),
                      r'C:\Program Files\Git\usr\bin\openssl.exe']
        self.exe = next((str(Path(p).resolve()) for p in candidatos
                         if p and Path(p).is_file()), None)
        if not self.exe:
            raise ErroCriptografia('OpenSSL não encontrado; use --openssl ou OPENSSL_EXE.')
        self.log = Path(log) if log else None

    def registrar(self, texto: str):
        if self.log:
            self.log.parent.mkdir(parents=True, exist_ok=True)
            with self.log.open('a', encoding='utf-8', newline='\n') as saida:
                saida.write(texto + '\n')

    def executar(self, *argumentos: str, verificar: bool = True) -> subprocess.CompletedProcess:
        argv = [str(x) for x in argumentos]
        self.registrar('$ ' + subprocess.list2cmdline(['openssl', *argv]))
        resultado = subprocess.run([self.exe, *argv], capture_output=True,
                                   encoding='utf-8', errors='replace', shell=False)
        for texto in [resultado.stdout, resultado.stderr]:
            if texto.strip():
                self.registrar(texto.rstrip())
        self.registrar(f'[código de saída: {resultado.returncode}]')
        if verificar and resultado.returncode:
            raise ErroCriptografia('OpenSSL falhou: ' + resultado.stderr.strip())
        return resultado


def _copiar_novo(origem: Path, destino: Path):
    destino.parent.mkdir(parents=True, exist_ok=True)
    with destino.open('xb') as saida, origem.open('rb') as entrada:
        shutil.copyfileobj(entrada, saida)


def gerar_chaves(ssl: OpenSSL, pasta: Path, prefixo: str = 'grupo') -> tuple[Path, Path]:
    pasta = Path(pasta).resolve()
    if not prefixo or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in prefixo):
        raise ErroCriptografia('Prefixo deve conter apenas letras, números, _ ou -.')
    privada, publica = pasta / f'{prefixo}_privada.pem', pasta / f'{prefixo}_publica.pem'
    if privada.exists() or publica.exists():
        raise ErroCriptografia('As chaves já existem; escolha outro prefixo ou pasta.')
    pasta.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.hibrida-', dir=pasta) as temp:
        t = Path(temp)
        ssl.executar('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                     '-out', str(t / 'privada.pem'))
        ssl.executar('rsa', '-in', str(t / 'privada.pem'), '-pubout', '-out', str(t / 'publica.pem'))
        _copiar_novo(t / 'privada.pem', privada)
        privada.chmod(0o600)
        _copiar_novo(t / 'publica.pem', publica)
    return privada, publica


def cifrar(ssl: OpenSSL, entrada: Path, publica: Path, pacote: Path) -> Path:
    entrada, publica, pacote = map(lambda p: Path(p).resolve(), (entrada, publica, pacote))
    if not entrada.is_file():
        raise ErroCriptografia('Arquivo de entrada não encontrado.')
    if pacote.exists():
        raise ErroCriptografia('A pasta do pacote já existe; nenhum arquivo foi sobrescrito.')
    ssl.executar('pkey', '-pubin', '-in', str(publica), '-noout')
    pacote.parent.mkdir(parents=True, exist_ok=True)
    # O diretório final contém apenas ciphertexts e parâmetros públicos.
    with tempfile.TemporaryDirectory(prefix='.hibrida-', dir=pacote.parent) as stage_dir:
        stage = Path(stage_dir)
        with tempfile.TemporaryDirectory(prefix='.hibrida-', dir=pacote.parent) as key_dir:
            segredo, senha = Path(key_dir) / 'chave_aes.bin', Path(key_dir) / 'senha_aes.txt'
            ssl.executar('rand', '-out', str(segredo), '32')
            if segredo.stat().st_size != 32:
                raise ErroCriptografia('O segredo deve ter 32 bytes.')
            ssl.executar('base64', '-A', '-in', str(segredo), '-out', str(senha))
            ssl.executar('enc', '-aes-256-cbc', '-salt', *KDF,
                         '-in', str(entrada), '-out', str(stage / 'mensagem.enc'),
                         '-pass', f'file:{senha}')
            ssl.executar('pkeyutl', '-encrypt', '-pubin', '-inkey', str(publica),
                         *OAEP, '-in', str(segredo), '-out', str(stage / 'chave_aes.enc'))
        (stage / 'parametros.json').write_text(json.dumps(PARAMETROS, indent=2) + '\n', encoding='utf-8')
        os.rename(stage, pacote)
    return pacote


def decifrar(ssl: OpenSSL, pacote: Path, privada: Path, saida: Path) -> Path:
    pacote, privada, saida = map(lambda p: Path(p).resolve(), (pacote, privada, saida))
    if saida.exists():
        raise ErroCriptografia('O arquivo de saída já existe; nenhum arquivo foi sobrescrito.')
    try:
        parametros = json.loads((pacote / 'parametros.json').read_text(encoding='utf-8'))
    except (OSError, ValueError) as erro:
        raise ErroCriptografia('Pacote ausente ou parâmetros inválidos.') from erro
    if parametros != PARAMETROS:
        raise ErroCriptografia('Formato ou parâmetros do pacote não suportados.')
    saida.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.hibrida-', dir=saida.parent) as temp:
        t = Path(temp)
        ssl.executar('pkeyutl', '-decrypt', '-inkey', str(privada), *OAEP,
                     '-in', str(pacote / 'chave_aes.enc'), '-out', str(t / 'chave_aes_restaurada.bin'))
        if (t / 'chave_aes_restaurada.bin').stat().st_size != 32:
            raise ErroCriptografia('O segredo recuperado deve ter 32 bytes.')
        ssl.executar('base64', '-A', '-in', str(t / 'chave_aes_restaurada.bin'),
                     '-out', str(t / 'senha_aes.txt'))
        ssl.executar('enc', '-d', '-aes-256-cbc', *KDF,
                     '-in', str(pacote / 'mensagem.enc'), '-out', str(t / 'restaurado'),
                     '-pass', f'file:{t / "senha_aes.txt"}')
        # O resultado só fica disponível quando o OpenSSL termina com sucesso.
        _copiar_novo(t / 'restaurado', saida)
    return saida
