from pathlib import Path
import os
import subprocess
import sys
import json
import pytest
from cripto_hibrida.arquivos import ErroCriptografia, sha256
from cripto_hibrida.chaves import gerar_chaves, carregar_privada, carregar_publica
from cripto_hibrida.cripto_hibrida import cifrar, decifrar
from cripto_hibrida.assinatura import assinar, verificar


@pytest.fixture(scope='session')
def ambiente(tmp_path_factory):
    pasta = tmp_path_factory.mktemp('chaves')
    privada, publica = gerar_chaves(pasta, 'destinatario')
    outra_privada, _ = gerar_chaves(pasta, 'outro')
    return privada, publica, outra_privada


@pytest.mark.parametrize('conteudo', [b'', 'Olá, Segurança de Software!\n'.encode(),
                                     bytes(range(256)), bytes(range(256)) * 4096],
                         ids=['vazio', 'utf8', 'binario', '1MiB'])
def test_round_trip(ambiente, tmp_path, conteudo):
    privada, publica, _ = ambiente
    entrada = tmp_path / 'arquivo original ç.bin'
    entrada.write_bytes(conteudo)
    pacote = cifrar(entrada, publica, tmp_path / 'pacote')
    restaurado = decifrar(pacote, privada, tmp_path / 'restaurado.bin')
    assert restaurado.read_bytes() == conteudo
    assert sha256(entrada) == sha256(restaurado)
    assert sorted(p.name for p in pacote.iterdir()) == ['chave_aes.enc', 'mensagem.enc', 'parametros.json']
    assert not list(tmp_path.glob('.hibrida-*'))
    print(f'ROUND-TRIP {len(conteudo)} bytes: {sha256(entrada)} = {sha256(restaurado)}')


def test_cifragem_e_aleatoria_por_arquivo(ambiente, tmp_path):
    _, publica, _ = ambiente
    entrada = tmp_path / 'm.txt'
    entrada.write_bytes(b'igual')
    a = cifrar(entrada, publica, tmp_path / 'a')
    b = cifrar(entrada, publica, tmp_path / 'b')
    assert (a / 'mensagem.enc').read_bytes() != (b / 'mensagem.enc').read_bytes()
    assert (a / 'chave_aes.enc').read_bytes() != (b / 'chave_aes.enc').read_bytes()


def test_chave_privada_errada_nao_produz_saida(ambiente, tmp_path):
    _, publica, errada = ambiente
    entrada = tmp_path / 'm.txt'
    entrada.write_bytes(b'mensagem')
    pacote = cifrar(entrada, publica, tmp_path / 'pacote')
    saida = tmp_path / 'saida.txt'
    with pytest.raises(ErroCriptografia):
        decifrar(pacote, errada, saida)
    assert not saida.exists()


def test_assinatura_e_adulteracao(ambiente, tmp_path):
    privada, publica, _ = ambiente
    arquivo = tmp_path / 'm.txt'
    arquivo.write_bytes(b'conteudo original')
    sig = assinar(arquivo, privada, tmp_path / 'm.sig')
    assert verificar(arquivo, publica, sig)
    arquivo.write_bytes(b'conteudo adulterado')
    assert not verificar(arquivo, publica, sig)


def test_nao_sobrescreve_arquivos(ambiente, tmp_path):
    privada, publica, _ = ambiente
    arquivo = tmp_path / 'm.txt'
    arquivo.write_bytes(b'preservar')
    pacote = cifrar(arquivo, publica, tmp_path / 'pacote')
    with pytest.raises(ErroCriptografia):
        cifrar(arquivo, publica, pacote)
    with pytest.raises(ErroCriptografia):
        decifrar(pacote, privada, arquivo)
    with pytest.raises(ErroCriptografia):
        gerar_chaves(privada.parent, 'destinatario')
    assert arquivo.read_bytes() == b'preservar'


def test_rejeita_parametros_inesperados(ambiente, tmp_path):
    privada, publica, _ = ambiente
    arquivo = tmp_path / 'm.txt'
    arquivo.write_bytes(b'teste')
    pacote = cifrar(arquivo, publica, tmp_path / 'pacote')
    meta = pacote / 'parametros.json'
    parametros = json.loads(meta.read_text())
    parametros['iteracoes'] = 1000000000000
    meta.write_text(json.dumps(parametros))
    with pytest.raises(ErroCriptografia, match='não suportados'):
        decifrar(pacote, privada, tmp_path / 'saida')


def test_cli_round_trip_e_assinatura(ambiente, tmp_path):
    privada, publica, _ = ambiente
    app = Path(__file__).resolve().parents[1] / 'app.py'
    arquivo, pacote, saida, sig = [tmp_path / n for n in ['original.bin', 'pacote', 'saida.bin', 'arquivo.sig']]
    arquivo.write_bytes(b'Round-trip executado pela CLI real.\x00\x0a\xff')

    def executar(*args, esperado=0):
        cmd = [sys.executable, str(app), *map(str, args)]
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
    proc = subprocess.run([sys.executable, str(app), 'gerar-chaves', '--pasta', str(tmp_path), '--prefixo', 'cli'],
                          capture_output=True, encoding='utf-8', errors='replace')
    assert proc.returncode == 0, proc.stderr
    assert carregar_privada(tmp_path / 'cli_privada.pem').key_size == 2048
    assert carregar_publica(tmp_path / 'cli_publica.pem').key_size == 2048


def test_aplicacao_funciona_sem_binarios_externos(tmp_path, monkeypatch):
    def proibido(*args, **kwargs):
        raise AssertionError('A aplicação não pode executar processos externos.')
    monkeypatch.setattr(subprocess, 'Popen', proibido)
    monkeypatch.setenv('PATH', '')
    privada, publica = gerar_chaves(tmp_path/'chaves', 'sem_binario')
    arquivo = tmp_path/'m.bin'
    arquivo.write_bytes(bytes(range(256)))
    pacote = cifrar(arquivo, publica, tmp_path/'pacote')
    restaurado = decifrar(pacote, privada, tmp_path/'saida.bin')
    assinatura = assinar(arquivo, privada, tmp_path/'m.sig')
    assert sha256(arquivo) == sha256(restaurado)
    assert verificar(restaurado, publica, assinatura)


def test_pdf_exemplo_round_trip(ambiente, tmp_path):
    privada, publica, _ = ambiente
    exemplo = Path(__file__).resolve().parents[1]/'exemplos/documento_teste.pdf'
    pacote = cifrar(exemplo, publica, tmp_path/'pacote_pdf')
    restaurado = decifrar(pacote, privada, tmp_path/'restaurado.pdf')
    assert restaurado.read_bytes() == exemplo.read_bytes()
    assert sha256(restaurado) == sha256(exemplo)
    print(f'ROUND-TRIP PDF: {sha256(exemplo)} = {sha256(restaurado)}')


def test_arquivo_cifrado_truncado_nao_produz_saida(ambiente, tmp_path):
    privada, publica, _ = ambiente
    original = tmp_path/'m.txt'
    original.write_bytes(b'teste de truncamento')
    pacote = cifrar(original, publica, tmp_path/'pacote')
    cifra = pacote/'mensagem.enc'
    cifra.write_bytes(cifra.read_bytes()[:-1])
    saida = tmp_path/'saida.txt'
    with pytest.raises(ErroCriptografia):
        decifrar(pacote, privada, saida)
    assert not saida.exists()


def test_rejeita_chave_ec_em_operacao_rsa(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    chave = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = tmp_path/'ec_publica.pem'
    pem.write_bytes(chave.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(ErroCriptografia, match='RSA'):
        carregar_publica(pem)
