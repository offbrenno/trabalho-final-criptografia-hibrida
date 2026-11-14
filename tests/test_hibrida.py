from pathlib import Path
import os
import subprocess
import sys
import json
import pytest
from hibrida.motor import (OpenSSL, ErroCriptografia, gerar_chaves, cifrar,
                           decifrar, assinar, verificar, sha256)


@pytest.fixture(scope='session')
def ambiente(tmp_path_factory):
    ssl = OpenSSL()
    pasta = tmp_path_factory.mktemp('chaves')
    privada, publica = gerar_chaves(ssl, pasta, 'destinatario')
    outra_privada, _ = gerar_chaves(ssl, pasta, 'outro')
    return ssl, privada, publica, outra_privada


@pytest.mark.parametrize('conteudo', [b'', 'Olá, Segurança de Software!\n'.encode(),
                                     bytes(range(256)), bytes(range(256)) * 4096],
                         ids=['vazio', 'utf8', 'binario', '1MiB'])
def test_round_trip(ambiente, tmp_path, conteudo):
    ssl, privada, publica, _ = ambiente
    entrada = tmp_path / 'arquivo original ç.bin'
    entrada.write_bytes(conteudo)
    pacote = cifrar(ssl, entrada, publica, tmp_path / 'pacote')
    restaurado = decifrar(ssl, pacote, privada, tmp_path / 'restaurado.bin')
    assert restaurado.read_bytes() == conteudo
    assert sha256(entrada) == sha256(restaurado)
    assert sorted(p.name for p in pacote.iterdir()) == ['chave_aes.enc', 'mensagem.enc', 'parametros.json']
    assert not list(tmp_path.glob('.hibrida-*'))
    print(f'ROUND-TRIP {len(conteudo)} bytes: {sha256(entrada)} = {sha256(restaurado)}')


def test_cifragem_e_aleatoria_por_arquivo(ambiente, tmp_path):
    ssl, _, publica, _ = ambiente
    entrada = tmp_path / 'm.txt'
    entrada.write_bytes(b'igual')
    a = cifrar(ssl, entrada, publica, tmp_path / 'a')
    b = cifrar(ssl, entrada, publica, tmp_path / 'b')
    assert (a / 'mensagem.enc').read_bytes() != (b / 'mensagem.enc').read_bytes()
    assert (a / 'chave_aes.enc').read_bytes() != (b / 'chave_aes.enc').read_bytes()


def test_chave_privada_errada_nao_produz_saida(ambiente, tmp_path):
    ssl, _, publica, errada = ambiente
    entrada = tmp_path / 'm.txt'
    entrada.write_bytes(b'mensagem')
    pacote = cifrar(ssl, entrada, publica, tmp_path / 'pacote')
    saida = tmp_path / 'saida.txt'
    with pytest.raises(ErroCriptografia):
        decifrar(ssl, pacote, errada, saida)
    assert not saida.exists()


def test_assinatura_e_adulteracao(ambiente, tmp_path):
    ssl, privada, publica, _ = ambiente
    arquivo = tmp_path / 'm.txt'
    arquivo.write_bytes(b'conteudo original')
    sig = assinar(ssl, arquivo, privada, tmp_path / 'm.sig')
    assert verificar(ssl, arquivo, publica, sig)
    arquivo.write_bytes(b'conteudo adulterado')
    assert not verificar(ssl, arquivo, publica, sig)


def test_nao_sobrescreve_arquivos(ambiente, tmp_path):
    ssl, privada, publica, _ = ambiente
    arquivo = tmp_path / 'm.txt'
    arquivo.write_bytes(b'preservar')
    pacote = cifrar(ssl, arquivo, publica, tmp_path / 'pacote')
    with pytest.raises(ErroCriptografia):
        cifrar(ssl, arquivo, publica, pacote)
    with pytest.raises(ErroCriptografia):
        decifrar(ssl, pacote, privada, arquivo)
    with pytest.raises(ErroCriptografia):
        gerar_chaves(ssl, privada.parent, 'destinatario')
    assert arquivo.read_bytes() == b'preservar'


def test_rejeita_parametros_inesperados(ambiente, tmp_path):
    ssl, privada, publica, _ = ambiente
    arquivo = tmp_path / 'm.txt'
    arquivo.write_bytes(b'teste')
    pacote = cifrar(ssl, arquivo, publica, tmp_path / 'pacote')
    meta = pacote / 'parametros.json'
    parametros = json.loads(meta.read_text())
    parametros['iteracoes'] = 1000000000000
    meta.write_text(json.dumps(parametros))
    with pytest.raises(ErroCriptografia, match='não suportados'):
        decifrar(ssl, pacote, privada, tmp_path / 'saida')


def test_cli_round_trip_e_assinatura(ambiente, tmp_path):
    ssl, privada, publica, _ = ambiente
    app = Path(__file__).resolve().parents[1] / 'app.py'
    arquivo, pacote, saida, sig = [tmp_path / n for n in ['original.bin', 'pacote', 'saida.bin', 'arquivo.sig']]
    arquivo.write_bytes(b'Round-trip executado pela CLI real.\x00\x0a\xff')

    def executar(*args, esperado=0):
        cmd = [sys.executable, str(app), '--openssl', ssl.exe, *map(str, args)]
        proc = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace')
        print('$ python app.py ' + ' '.join(map(str, args)))
        print(proc.stdout.strip())
        assert proc.returncode == esperado, proc.stderr

    executar('cifrar', '--entrada', arquivo, '--publica', publica, '--pacote', pacote)
    executar('decifrar', '--pacote', pacote, '--privada', privada, '--saida', saida)
    executar('assinar', '--entrada', arquivo, '--privada', privada, '--assinatura', sig)
    executar('verificar', '--entrada', saida, '--publica', publica, '--assinatura', sig)
    assert sha256(arquivo) == sha256(saida)
    saida.write_bytes(saida.read_bytes() + b'alteracao')
    executar('verificar', '--entrada', saida, '--publica', publica, '--assinatura', sig, esperado=1)


def test_cli_geracao_de_chaves(tmp_path):
    app = Path(__file__).resolve().parents[1] / 'app.py'
    ssl = OpenSSL()
    proc = subprocess.run([sys.executable, str(app), '--openssl', ssl.exe,
                           'gerar-chaves', '--pasta', str(tmp_path), '--prefixo', 'cli'],
                          capture_output=True, encoding='utf-8', errors='replace')
    assert proc.returncode == 0, proc.stderr
    ssl.executar('pkey', '-in', str(tmp_path / 'cli_privada.pem'), '-check', '-noout')
    ssl.executar('pkey', '-pubin', '-in', str(tmp_path / 'cli_publica.pem'), '-noout')
