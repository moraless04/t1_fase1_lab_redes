# Relatório — Fase 2: Interceptação e alteração de mensagens (MITM)

**Disciplina:** Laboratório de Redes de Computadores
**Grupo:** Arthur Ávila dos Santos e Samuel da Silva Morales

## 1. Objetivo

Demonstrar, em laboratório isolado, como um proxy intermediário pode
ler e alterar mensagens de um protocolo de aplicação que trafega em
texto claro, comprometendo a integridade dos dados.

## 2. Topologia utilizada

A demonstração foi executada com containers Podman no Codespace.

| Componente | Endereço | Porta | Função |
|---|---|---|---|
| Cliente | 10.89.0.3 | TCP de origem dinâmica | Envia comandos CVP |
| Proxy MITM | 10.89.0.12 | TCP/5051 | Intercepta e altera mensagens |
| Servidor CVP | 10.89.0.10 | TCP/5050 | Processa os comandos recebidos |

O proxy recebe a conexão do cliente e abre outra conexão TCP com o
servidor. Portanto, existem dois trechos de comunicação.

## 3. Funcionamento do ataque demonstrado

O proxy examina as mensagens CVP delimitadas por nova linha.
Na demonstração, a mensagem:

`SET cofre_saldo 15000`

é substituída por:

`SET cofre_saldo 90000`

O servidor recebe a mensagem modificada e confirma a gravação.

## 4. Resultados observados

Na execução demonstrada, o cliente recebeu:

- `OK cofre_saldo gravado`
- `OK cofre_saldo=90000`

O log do proxy registrou a substituição de `15000` por `90000`.
A captura PCAP foi aberta no Wireshark e o fluxo TCP foi reconstruído,
exibindo mensagens CVP em texto claro.

## 5. Evidências

Os arquivos de evidência ficam em `evidencias/fase2/`:

- `fase2-mitm.pcap`: captura do trecho proxy-servidor.
- `01-wireshark-pacotes.png`: lista de pacotes TCP.
- `02-wireshark-fluxo-tcp.png`: fluxo TCP reconstruído.
- `02-concorrencia.png`: evidência do teste de concorrência.
- `03-proxy-alteracao.png`: log do proxy com a alteração.

A captura existente representa o trecho proxy-servidor na porta TCP 5050.
Ela não deve ser apresentada como captura simultânea dos dois trechos
da conexão, pois o cliente se conecta ao proxy pela porta 5051.

## 6. Limitações

A demonstração atual usa mensagens em texto claro e uma regra de
alteração específica para o comando `SET cofre_saldo 15000`.
O proxy processa mensagens delimitadas por linha, com limite de tamanho.

O ambiente utilizado foi Podman no Codespace; ele não representa
três máquinas virtuais independentes.

## 7. Conclusão

O experimento demonstra que um intermediário capaz de receber e
encaminhar as conexões pode modificar um comando sem que o protocolo
CVP forneça um mecanismo criptográfico de integridade para detectar
a alteração. A resposta do servidor e a leitura posterior do valor
confirmam o efeito observado na demonstração.
