"""Protótipo didático da Atividade 16. Requer Python 3.10+ e OpenSSL 3.x."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

OAEP = ['-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt',
        'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256']
KDF = ['-pbkdf2', '-iter', '100000', '-md', 'sha256']


def localizar_openssl(informado: str | None) -> str:
    candidatos = [informado, os.environ.get('OPENSSL_EXE'),
                  shutil.which('openssl'),
                  r'C:\Program Files\Git\usr\bin\openssl.exe']
    for candidato in candidatos:
        if candidato and Path(candidato).is_file():
            return str(Path(candidato).resolve())
    raise RuntimeError('OpenSSL não encontrado. Use --openssl CAMINHO_DO_EXECUTAVEL.')


class Terminal:
    def __init__(self, exe: str, pasta: Path):
        self.exe, self.pasta = exe, pasta
        self.linhas: list[str] = []

    def escrever(self, texto: str):
        self.linhas.append(texto)
        print(texto, flush=True)

    def executar(self, *argumentos: str, esperado: int = 0) -> str:
        self.escrever('$ ' + subprocess.list2cmdline(['openssl', *argumentos]))
        proc = subprocess.run([self.exe, *argumentos], cwd=self.pasta,
                              capture_output=True, text=True,
                              encoding='utf-8', errors='replace', shell=False)
        saida = proc.stdout.strip()
        if saida:
            self.escrever(saida)
        # A geração RSA imprime indicadores aleatórios de progresso em stderr.
        # Omitimos só esse progresso; os demais diagnósticos são preservados.
        if proc.stderr.strip() and argumentos[0] != 'genpkey':
            self.escrever(proc.stderr.strip())
        self.escrever(f'[código de saída: {proc.returncode}]')
        if proc.returncode != esperado:
            raise RuntimeError(f'Falha em {argumentos[0]}: {proc.stderr.strip()}')
        return saida

    def salvar(self):
        (self.pasta / 'log_execucao.txt').write_text(
            '\n'.join(self.linhas) + '\n', encoding='utf-8')


def demonstrar(args):
    exe = localizar_openssl(args.openssl)
    pasta = Path(args.pasta).resolve()
    if pasta.exists() and any(pasta.iterdir()):
        raise RuntimeError('A pasta de execução deve estar vazia ou ainda não existir.')
    pasta.mkdir(parents=True, exist_ok=True)
    if args.entrada:
        conteudo = Path(args.entrada).read_bytes()
    else:
        conteudo = (
            'Atividade 16 - Criptografia Híbrida e Checkpoint 1\n'
            'Disciplina: Segurança de Software.\n'
            'Este arquivo será cifrado com AES-256-CBC e PBKDF2.\n'
            'O segredo aleatório será protegido com RSA-2048 e OAEP-SHA256.\n'
            'Após a decriptação, o conteúdo e o hash SHA-256 devem ser idênticos.\n'
        ).encode('utf-8')
    (pasta / 'mensagem.txt').write_bytes(conteudo)
    terminal = Terminal(exe, pasta)
    try:
        agora = datetime.now(ZoneInfo('America/Sao_Paulo')).isoformat(timespec='seconds')
        terminal.escrever(f'Execução real: {agora}')
        terminal.escrever(f'Aplicação: Python {sys.version.split()[0]} / interface CLI')
        versao = terminal.executar('version')
        terminal.escrever(f'mensagem.txt: {len(conteudo)} bytes')
        terminal.executar('genpkey', '-algorithm', 'RSA', '-pkeyopt',
                          'rsa_keygen_bits:2048', '-out', 'privada.pem')
        terminal.executar('rsa', '-in', 'privada.pem', '-pubout', '-out', 'publica.pem')
        terminal.executar('rand', '-out', 'chave_aes.bin', '32')
        assert (pasta / 'chave_aes.bin').stat().st_size == 32
        terminal.escrever('chave_aes.bin: 32 bytes (256 bits), tamanho confirmado')
        segredo_bruto = (pasta / 'chave_aes.bin').read_bytes()
        terminal.escrever(f'Inspeção binária: 0x0A presente={10 in segredo_bruto}; 0x00 presente={0 in segredo_bruto}')
        terminal.escrever('Decisão: Base64 em linha única, preservando os 32 bytes como entrada de PBKDF2.')
        terminal.executar('base64', '-A', '-in', 'chave_aes.bin', '-out', 'senha_aes.txt')
        terminal.executar('enc', '-aes-256-cbc', '-salt', *KDF,
                          '-in', 'mensagem.txt', '-out', 'mensagem.enc',
                          '-pass', 'file:senha_aes.txt')
        terminal.executar('pkeyutl', '-encrypt', '-pubin', '-inkey', 'publica.pem',
                          '-in', 'chave_aes.bin', '-out', 'chave_aes.enc', *OAEP)
        terminal.executar('pkeyutl', '-decrypt', '-inkey', 'privada.pem',
                          '-in', 'chave_aes.enc', '-out', 'chave_aes_restaurada.bin', *OAEP)
        terminal.executar('base64', '-A', '-in', 'chave_aes_restaurada.bin',
                          '-out', 'senha_aes_recuperada.txt')
        terminal.executar('enc', '-d', '-aes-256-cbc', *KDF,
                          '-in', 'mensagem.enc', '-out', 'mensagem_restaurada.txt',
                          '-pass', 'file:senha_aes_recuperada.txt')
        terminal.executar('dgst', '-sha256', 'mensagem.txt', 'mensagem_restaurada.txt')
        restaurado = (pasta / 'mensagem_restaurada.txt').read_bytes()
        segredo = (pasta / 'chave_aes.bin').read_bytes()
        segredo_restaurado = (pasta / 'chave_aes_restaurada.bin').read_bytes()
        if segredo != segredo_restaurado or conteudo != restaurado:
            raise RuntimeError('O round-trip não preservou os bytes originais.')
        terminal.escrever('Comparação Python dos bytes: chave_aes.bin == chave_aes_restaurada.bin: True')
        terminal.escrever('ROUND-TRIP: OK (segredo e arquivo iguais byte a byte)')
        terminal.executar('dgst', '-sha256', '-sign', 'privada.pem',
                          '-out', 'mensagem.sig', 'mensagem.txt')
        terminal.executar('dgst', '-sha256', '-verify', 'publica.pem',
                          '-signature', 'mensagem.sig', 'mensagem_restaurada.txt')
        (pasta / 'mensagem_adulterada.txt').write_bytes(conteudo + b'ALTERADO\n')
        terminal.executar('dgst', '-sha256', '-verify', 'publica.pem',
                          '-signature', 'mensagem.sig', 'mensagem_adulterada.txt', esperado=1)
        terminal.escrever('CONTROLE NEGATIVO: OK (assinatura rejeitou arquivo adulterado)')
        resultado = {
            'data_execucao': agora, 'openssl': versao,
            'rsa_bits': 2048, 'segredo_bytes': 32, 'pbkdf2_iteracoes': 100000,
            'arquivo_bytes': len(conteudo),
            'sha256_original': hashlib.sha256(conteudo).hexdigest(),
            'sha256_restaurado': hashlib.sha256(restaurado).hexdigest(),
            'round_trip': True, 'assinatura_valida': True,
            'adulteracao_rejeitada': True,
            'tamanhos_bytes': {nome: (pasta / nome).stat().st_size for nome in
                              ['mensagem.txt', 'mensagem.enc', 'chave_aes.bin',
                               'chave_aes.enc', 'mensagem_restaurada.txt', 'mensagem.sig']},
        }
        (pasta / 'resultado.json').write_text(
            json.dumps(resultado, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        terminal.escrever('RESULTADO FINAL: SUCESSO')
    finally:
        terminal.salvar()


def main():
    parser = argparse.ArgumentParser(description='Simulação de criptografia híbrida com evidências reais.')
    parser.add_argument('--pasta', default='execucao', help='Pasta nova ou vazia para os resultados.')
    parser.add_argument('--entrada', help='Arquivo opcional para testar, inclusive binário.')
    parser.add_argument('--openssl', help='Caminho do executável OpenSSL.')
    args = parser.parse_args()
    try:
        demonstrar(args)
    except (OSError, RuntimeError, AssertionError, subprocess.SubprocessError) as erro:
        print(f'ERRO: {erro}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
