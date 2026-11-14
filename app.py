"""Interface CLI para a aplicação de criptografia híbrida."""
import argparse
from pathlib import Path
import sys
from hibrida.motor import OpenSSL, ErroCriptografia, gerar_chaves, cifrar, decifrar, assinar, verificar, sha256


def main(argv=None):
    parser = argparse.ArgumentParser(description='Criptografia híbrida AES-256-CBC/PBKDF2 e RSA-OAEP.')
    parser.add_argument('--openssl', help='Executável OpenSSL (ou configure OPENSSL_EXE).')
    parser.add_argument('--log', type=Path, help='Anexar comandos e respostas do OpenSSL a este log.')
    comandos = parser.add_subparsers(dest='comando', required=True)
    gerar = comandos.add_parser('gerar-chaves', help='Criar par RSA de 2048 bits.')
    gerar.add_argument('--pasta', type=Path, default=Path('chaves'))
    gerar.add_argument('--prefixo', default='grupo')
    enc = comandos.add_parser('cifrar', help='Criar pacote cifrado para o destinatário.')
    enc.add_argument('--entrada', type=Path, required=True)
    enc.add_argument('--publica', type=Path, required=True)
    enc.add_argument('--pacote', type=Path, required=True)
    dec = comandos.add_parser('decifrar', help='Restaurar arquivo usando a chave privada.')
    dec.add_argument('--pacote', type=Path, required=True)
    dec.add_argument('--privada', type=Path, required=True)
    dec.add_argument('--saida', type=Path, required=True)
    sig = comandos.add_parser('assinar', help='Assinar arquivo com RSA e SHA-256.')
    sig.add_argument('--entrada', type=Path, required=True)
    sig.add_argument('--privada', type=Path, required=True)
    sig.add_argument('--assinatura', type=Path, required=True)
    ver = comandos.add_parser('verificar', help='Verificar assinatura; retorna 1 se inválida.')
    ver.add_argument('--entrada', type=Path, required=True)
    ver.add_argument('--publica', type=Path, required=True)
    ver.add_argument('--assinatura', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        ssl = OpenSSL(args.openssl, args.log)
        if args.comando == 'gerar-chaves':
            privada, publica = gerar_chaves(ssl, args.pasta, args.prefixo)
            print(f'Par RSA-2048 criado. Privada local: {privada}; pública: {publica}')
        elif args.comando == 'cifrar':
            print(f'Pacote criado: {cifrar(ssl, args.entrada, args.publica, args.pacote)}')
        elif args.comando == 'decifrar':
            arquivo = decifrar(ssl, args.pacote, args.privada, args.saida)
            print(f'Arquivo restaurado: {arquivo}\nSHA-256: {sha256(arquivo)}')
        elif args.comando == 'assinar':
            print(f'Assinatura criada: {assinar(ssl, args.entrada, args.privada, args.assinatura)}')
        elif args.comando == 'verificar':
            valido = verificar(ssl, args.entrada, args.publica, args.assinatura)
            print('Verified OK' if valido else 'Verification failure')
            return 0 if valido else 1
        return 0
    except (ErroCriptografia, OSError) as erro:
        print(f'ERRO: {erro}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
