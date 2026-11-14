# Segurança de Software - base do Trabalho Final

UniRV - Engenharia de Software, 3º período - Campus Rio Verde.
Professor: Vinícius Martinez de Oliveira. Atividade 16, de 13/11/2026.

## Integrantes

1. Brenno Rego de Oliveira
2. Matheus Almeida Rodrigues
3. João Vitor Silva Martins

Repositório público: <https://github.com/offbrenno/trabalho-final-criptografia-hibrida>.

## O que está implementado

Aplicação Python 3 com CLI (`argparse`), geração de chaves RSA-2048, cifragem e
decifragem híbrida AES-256-CBC/PBKDF2 + RSA-OAEP/SHA-256, e assinatura destacada
de arquivos genéricos com RSA/SHA-256. Essas operações usam a biblioteca
`cryptography` diretamente e funcionam sem executar o binário `openssl`.

A assinatura genérica é um arquivo `.sig` separado. Ela não insere uma
assinatura no PDF e não aparece como assinatura digital no Adobe Acrobat Reader.
O PDF de exemplo é um documento comum, sem assinatura digital embutida.

## Requisitos e instalação do zero

Python 3.11 ou superior. Instalação e testes verificados com Python 3.12.14,
`cryptography==50.0.2` e `pytest==9.2.0`, em ambiente virtual novo.

Windows PowerShell, dentro da pasta clonada:

```powershell
git clone https://github.com/offbrenno/trabalho-final-criptografia-hibrida.git
cd trabalho-final-criptografia-hibrida
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -v -s
.\.venv\Scripts\python.exe app.py --help
```

Linux/macOS: use `.venv/bin/python` no lugar de `.\.venv\Scripts\python.exe`.
`requirements.txt` instala as dependências e o pacote local em modo editável.
O comando `cripto-hibrida` também fica disponível no ambiente virtual.

## Uso da CLI

Nos comandos a seguir, `python` representa o interpretador do ambiente virtual.
Não reutilize um caminho de saída existente: a aplicação impede sobrescritas.
Gere um par de teste local com prefixo novo; o Git contém somente chaves públicas.

```powershell
python app.py gerar-chaves --pasta chaves --prefixo meu_teste
python app.py cifrar --entrada exemplos/documento_teste.pdf --publica chaves/meu_teste_publica.pem --pacote pacotes/teste
python app.py decifrar --pacote pacotes/teste --privada chaves/meu_teste_privada.pem --saida execucoes/restaurado.pdf
python app.py assinar --entrada exemplos/documento_teste.pdf --privada chaves/meu_teste_privada.pem --assinatura execucoes/documento.sig
python app.py verificar --entrada execucoes/restaurado.pdf --publica chaves/meu_teste_publica.pem --assinatura execucoes/documento.sig
```

`--log CAMINHO`, antes do subcomando, registra os resultados da aplicação.
Retornos: 0 para sucesso, 1 para assinatura incompatível e 2 para erro de operação
ou argumentos. A opção antiga `--openssl` foi removida da aplicação.

## Formato e compatibilidade da criptografia híbrida

Cada cifragem gera um novo segredo aleatório de 32 bytes. O RSA-OAEP protege
esses bytes usando SHA-256 tanto no OAEP quanto no MGF1. O pacote contém
`mensagem.enc`, `chave_aes.enc` e `parametros.json`.

Foi mantido o formato v1 usado na Atividade 16: `mensagem.enc` começa com
`Salted__`, seguido do salt de 8 bytes e do conteúdo cifrado com padding PKCS#7.
Para preservar a compatibilidade, o segredo é representado em Base64 e usado
como entrada de PBKDF2-HMAC-SHA256, com 100.000 iterações e 48 bytes de saída:
32 para a chave AES-256 e 16 para o IV. O salt de 8 bytes é uma decisão de
compatibilidade com os pacotes OpenSSL 3.2.1 já produzidos, não uma escolha de
formato para o Trabalho Final futuro.

Essa codificação evita tratar bytes 0x00 e 0x0A como senha textual truncada na
prática com `-pass file:`. Na aplicação migrada, o segredo e a chave derivada
ficam em memória e não são gravados como senha ou `chave_aes.bin` no disco.
Foram verificadas a leitura de um pacote antigo e a interoperabilidade com
OpenSSL nos dois sentidos; o log está em `evidencias/compatibilidade.log`.

CBC fornece confidencialidade, mas não autentica os dados. A assinatura destacada
deve ser verificada antes de confiar no conteúdo restaurado. Ela não autentica
todo o envelope de transporte. Este é um projeto acadêmico, não um protocolo de
mensageria autenticada. As chaves privadas de teste ficam sem senha apenas para
o fluxo didático local; suporte a privadas protegidas por senha ainda não existe.

## Estrutura

```text
app.py                         entrada da CLI
src/cripto_hibrida/chaves.py    geração e leitura de chaves RSA
src/cripto_hibrida/cripto_hibrida.py  cifragem e decifragem
src/cripto_hibrida/assinatura.py     assinatura genérica destacada
src/cripto_hibrida/arquivos.py       hash e escrita de arquivos
src/cripto_hibrida/cli.py            comandos argparse
tests/                         testes automatizados
exemplos/                      mensagem e PDF comum de teste
chaves/                        somente chaves públicas no Git
evidencias/                    logs reais da atividade e dos testes
scripts/pratica_openssl.py     prática de terminal da Parte 2
requirements.txt              dependências e instalação do pacote
```

## Testes e evidências

```powershell
python -m pytest -v -s
```

Os testes verificam hashes e bytes no round-trip de arquivos vazios, texto UTF-8,
dados binários de até 1 MiB e um PDF comum; a execução da CLI; aleatoriedade por
arquivo; assinatura e adulteração; privada errada; truncamento; parâmetros
inesperados; preservação de saídas; rejeição de chave não RSA; e funcionamento
com processos externos bloqueados. Saída real: `evidencias/pytest_cryptography.log`.
Round-trip da CLI atual: `evidencias/aplicacao_cryptography.log`.

As evidências anteriores foram preservadas como registros históricos da
Atividade 16. Os arquivos `evidencias/aplicacao_openssl.log` e `evidencias/pytest.log`
descrevem a versão anterior; não descrevem o motor atual.
Nos logs públicos, apenas os caminhos locais são normalizados e identificados;
hashes e resultados são mantidos. Os originais ficam fora do Git, em `entrega/`.

O OpenSSL externo é necessário somente para repetir a prática de terminal:

```powershell
python scripts/pratica_openssl.py --pasta execucoes/parte2_nova
```

Esse script exige OpenSSL 3.x e, no Windows, `tzdata` se a base de fusos não
estiver disponível. Isso não é requisito de execução da aplicação migrada.

## Chaves e arquivos locais

`.gitignore` bloqueia PEM em geral, liberando somente os caminhos de chaves
públicas; também bloqueia `chave_aes*.bin`, senhas, `.key`, `.p12`, `.pfx`, ambientes
virtuais, arquivos temporários, pacotes cifrados e assinaturas binárias.
Nunca use `git add -f` para incluir uma privada ou senha.

O par do grupo foi mantido no computador de origem: `chaves/grupo_privada.pem`
é local e ignorada; `chaves/grupo_publica.pem` pode ser compartilhada.
A chave do professor não foi gerada por este projeto. Um certificado público de
exemplo só será adicionado quando a etapa X.509 do roadmap for implementada.

## Roadmap - Trabalho Final ainda não implementado

Este repositório é a base do Trabalho Final **Aplicação para Assinatura e
Validação Digital de Documentos PDF**. As etapas abaixo são futuras:

- Gerar certificado X.509 autoassinado com RSA de pelo menos 2048 bits.
- Inserir assinatura digital real em PDF, verificável no Adobe Acrobat Reader.
- Validar assinatura de PDF e distinguir integridade inválida de certificado
  autoassinado ou não confiável.
- Detectar e apresentar alterações posteriores à assinatura de PDF.
- Incluir exemplos de PDF assinado e certificado público, com documentação.

Nenhuma dessas funcionalidades foi implementada nesta revisão. O comando atual
`assinar` produz exclusivamente uma assinatura genérica destacada `.sig`.

## Referências

- [cryptography: RSA](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)
- [cryptography: cifras simétricas](https://cryptography.io/en/stable/hazmat/primitives/symmetric-encryption/)
- [cryptography: PBKDF2](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/)
- [OpenSSL enc](https://docs.openssl.org/3.5/man1/openssl-enc/)
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)
