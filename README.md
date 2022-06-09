# Padding Oracle Attack

Implementação do Padding Oracle Attack de Vaudenay (2002) para o curso de 
criptografia do PPGCC - PUCRS.

## Pré-Requisitos

* Compilador `g++` com suporte à std `c++20`
* Biblioteca `boost` (`program_options`)
* Biblioteca `cpr`
* Biblioteca `cryptopp`

## Compilando

```
meson build
ninja -C build
```

## Executando

```
$ ./poa --help
Padding Oracle Attack (for ASCII data):
  --url arg             URL to attack
  --help                produce help message
```
