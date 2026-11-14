# Trabalho Final - Criptografia Híbrida

UniRV, Engenharia de Software (3º período), Campus Rio Verde.
Segurança de Software. Professor: Vinícius Martinez de Oliveira.

## Integrantes

- Brenno Rego de Oliveira
- Matheus Almeida Rodrigues
- João Vitor Silva Martins

Aplicação em Python 3 com interface de linha de comando (CLI/argparse).
Desenvolvimento inicial: 13/11/2026.

## Requisitos e instalação

Python 3.10+ e OpenSSL 3.x. A aplicação usa apenas a biblioteca padrão do Python.
No Windows, o OpenSSL fornecido pelo Git for Windows é reconhecido automaticamente.
Também é possível definir `OPENSSL_EXE` ou usar `python app.py --openssl CAMINHO ...`.

Para os testes:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -v -s
```

Os 11 testes exercitam round-trip de arquivos vazios, UTF-8 e binários de até
1 MiB, aleatoriedade por arquivo, chave privada errada, assinatura e adulteração,
preservação de saídas existentes, validação de parâmetros e execução real da CLI.
O log da execução verificada está em `evidencias/pytest.log`.

## Uso dos cinco comandos

As opções globais `--openssl` e `--log` vêm antes do comando. Nenhuma operação
sobrescreve chaves, assinaturas, arquivos de saída ou pacotes existentes.

```powershell
python app.py gerar-chaves --pasta chaves --prefixo meu_teste
python app.py cifrar --entrada exemplos/mensagem.txt --publica chaves/meu_teste_publica.pem --pacote pacotes/teste
python app.py decifrar --pacote pacotes/teste --privada chaves/meu_teste_privada.pem --saida execucoes/restaurada.txt
python app.py assinar --entrada exemplos/mensagem.txt --privada chaves/meu_teste_privada.pem --assinatura execucoes/mensagem.sig
python app.py verificar --entrada execucoes/restaurada.txt --publica chaves/meu_teste_publica.pem --assinatura execucoes/mensagem.sig
openssl dgst -sha256 exemplos/mensagem.txt execucoes/restaurada.txt
```

Crie `execucoes/` antes de usar `pytest --basetemp=execucoes/teste` se optar por
uma pasta temporária explícita. Sem essa opção, pytest escolhe a própria pasta.
Use novo prefixo/pacote/caminho a cada execução. Retornos da CLI: 0 para sucesso,
1 para assinatura inválida e 2 para erro de operação/argumentos.

## Formato do pacote e decisão técnica

Cada cifragem gera um novo segredo aleatório de 32 bytes, sem reutilização entre
arquivos. A pasta de saída contém apenas `mensagem.enc`, `chave_aes.enc` e
`parametros.json`; os parâmetros são públicos, fixos e validados na decifragem.
O segredo binário é cifrado por RSA-OAEP com SHA-256 e MGF1-SHA256.

O AES-256-CBC usa `-pbkdf2 -iter 100000 -md sha256` e salt aleatório. Para cumprir
o enunciado sem o problema de bytes 0x0A/0x00 em `-pass file:`, o segredo é
codificado em Base64, em uma única linha, antes de ser fornecido ao OpenSSL.
Base64 é representação, não cifragem. PBKDF2 deriva a chave AES efetiva e o IV
a partir dessa representação. Os 32 bytes protegidos pelo RSA são o material
secreto de entrada; não são aplicados diretamente com `-K` ao AES.

As senhas textuais e os segredos ficam em pastas temporárias e são removidos
ao concluir as operações. A limpeza não equivale a apagamento físico garantido
do disco. A chave privada de longo prazo fica exclusivamente na pasta local.

CBC não é uma cifra autenticada. Verifique a assinatura do conteúdo restaurado
antes de confiar nele. A assinatura é separada do pacote e não autentica todos
os metadados do transporte. Este projeto é uma demonstração acadêmica.

No envio real, use a pública do professor para cifrar o segredo e a privada do
grupo para assinar. O professor decifra com sua privada e verifica com a pública
do grupo, obtida por um canal de identidade confiável. A simulação usa pares
locais. O par oficial do grupo é separado do par de teste da Parte 2.

## Parte 2 reproduzível

```powershell
python scripts/pratica_openssl.py --pasta execucoes/parte2_nova
```

Esse script exige base de fusos disponível ao Python (`python -m pip install
tzdata` no Windows, se necessário). Gera os nomes de arquivos exigidos, inspeciona
a presença de 0x0A e 0x00 sem revelar o segredo e grava comandos, saídas, hashes e
comparações de bytes. A pasta deve ser nova ou vazia.

## Chaves, logs e Git

Somente chaves públicas são versionadas. `.gitignore` bloqueia todos os PEM e
permite novamente nomes terminados em `publica.pem`; também bloqueia
`chave_aes*.bin`, senhas, execução local e `entrega/`. Nunca use `git add -f` para
incluir privadas ou segredos. `.gitattributes` preserva os bytes das evidências.
Arquivos binários cifrados e assinaturas (`*.enc` e `*.sig`) também ficam somente
na pasta de execução/entrega local; os logs públicos registram os seus testes.

O par do grupo foi gerado em `chaves/grupo_privada.pem` e
`chaves/grupo_publica.pem`. A privada não é incluída no Git nem no ZIP de
distribuição. Para uma instalação a partir do Git/ZIP, gere outro par local com
novo prefixo; a privada original permanece somente no computador de origem.

`evidencias/` contém os registros reais de OpenSSL, da aplicação e do pytest.
Nos registros públicos, somente caminhos absolutos do computador foram
normalizados para `[PROJETO]`, `python` ou `[USUARIO_LOCAL]`; essa alteração é
identificada no próprio log. Os hashes e resultados foram preservados. As cópias
originais estão em `entrega/evidencias_originais/`, fora do Git, e são usadas no PDF.
`evidencias/fingerprint_grupo.txt` registra o SHA-256 do SubjectPublicKeyInfo DER
da pública do grupo. Não contém chaves privadas ou segredos em texto claro.

## Referências

- [OpenSSL enc](https://docs.openssl.org/3.5/man1/openssl-enc/)
- [OpenSSL pkeyutl](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/)
- [OpenSSL dgst](https://docs.openssl.org/3.5/man1/openssl-dgst/)
- [Opções de senha](https://docs.openssl.org/3.5/man1/openssl-passphrase-options/)
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)
