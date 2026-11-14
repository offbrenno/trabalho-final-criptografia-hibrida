"""Interface CLI para a aplicação de criptografia híbrida."""
import argparse
from pathlib import Path
import sys
from .arquivos import ErroCriptografia, sha256
from .chaves import gerar_chaves
from .cripto_hibrida import cifrar, decifrar
from .assinatura import assinar, verificar


def main(argv=None):
    parser = argparse.ArgumentParser(description='Criptografia híbrida AES-256-CBC/PBKDF2 e RSA-OAEP.')
    parser.add_argument('--log', type=Path, help='Anexar resumo das operações e resultados a este log.')
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
    def emitir(texto):
        print(texto)
        if args.log:
            args.log.parent.mkdir(parents=True, exist_ok=True)
            with args.log.open('a', encoding='utf-8') as arquivo:
                arquivo.write(texto + '\n')

    try:
        if args.comando == 'gerar-chaves':
            privada, publica = gerar_chaves(args.pasta, args.prefixo)
            emitir(f'Par RSA-2048 criado em {args.pasta}; pública: {publica.name}; privada somente local.')
        elif args.comando == 'cifrar':
            cifrar(args.entrada, args.publica, args.pacote)
            emitir(f'Pacote criado: {args.pacote}')
        elif args.comando == 'decifrar':
            arquivo = decifrar(args.pacote, args.privada, args.saida)
            emitir(f'Arquivo restaurado: {args.saida}\nSHA-256: {sha256(arquivo)}')
        elif args.comando == 'assinar':
            assinar(args.entrada, args.privada, args.assinatura)
            emitir(f'Assinatura criada: {args.assinatura}')
        elif args.comando == 'verificar':
            valido = verificar(args.entrada, args.publica, args.assinatura)
            emitir('Verified OK' if valido else 'Verification failure')
            return 0 if valido else 1
        return 0
    except (ErroCriptografia, OSError) as erro:
        print(f'ERRO: {erro}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
