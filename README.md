# OpenVPN Monitor Fast

Página de status somente leitura para OpenVPN. A aplicação lê o arquivo de
status CSV produzido pelo próprio OpenVPN, mantém o último snapshot válido em
memória e não consulta a interface de management durante as requisições.

## Recursos

- página HTML responsiva com busca, ordenação e paginação;
- cache invalidado pelo `mtime` e tamanho do arquivo de status;
- proteção contra leituras incompletas e arquivos maiores que o limite;
- escape de valores externos antes da geração do HTML;
- `GET /healthz` para verificação de saúde;
- `GET /?get_json=1` compatível com o contrato legado `identidade: IP_VPN`;
- execução direta para desenvolvimento e WSGI/Gunicorn para produção.

## Requisitos

A aplicação usa apenas a biblioteca padrão do Python e suporta Python 3.8 ou
superior. A implantação de referência usa Gunicorn 21.2.0, fixado em
`requirements.txt`.

## Execução local

Nenhuma dependência adicional é necessária para iniciar com o servidor WSGI
de desenvolvimento. O repositório contém um status fictício, sem dados reais:

```bash
python3 openvpn_monitor_fast.py \
  --status-path examples/openvpn-status.log
```

A página ficará disponível somente no loopback:

```text
http://127.0.0.1:8081/
```

Consulte todas as opções com:

```bash
python3 openvpn_monitor_fast.py --help
```

Para ler um status real, o usuário que executa o processo precisa ter
permissão de leitura:

```bash
python3 openvpn_monitor_fast.py \
  --status-path /var/log/openvpn/openvpn-status.log \
  --site "OpenVPN Monitor"
```

O servidor embutido é destinado a desenvolvimento e diagnóstico. Use
Gunicorn em produção.

## Configuração

A execução direta aceita opções de linha de comando. Tanto ela quanto o
Gunicorn reconhecem estas variáveis de ambiente:

| Variável | Padrão | Uso |
| --- | --- | --- |
| `OPENVPN_STATUS_PATH` | `/var/log/openvpn/openvpn-status.log` | Arquivo CSV de status |
| `OPENVPN_MONITOR_SITE` | `OpenVPN Monitor` | Nome exibido na página |
| `OPENVPN_MONITOR_PAGE_SIZE` | `200` | Linhas por página, limitado de 25 a 500 |
| `OPENVPN_STATUS_MAX_BYTES` | `8388608` | Tamanho máximo aceito para o status |
| `OPENVPN_MONITOR_BIND` | `127.0.0.1` na execução direta | Endereço de escuta |
| `OPENVPN_MONITOR_PORT` | `8081` | Porta usada apenas na execução direta |

Na execução direta, argumentos explícitos prevalecem sobre as variáveis de
ambiente.

## Configuração do OpenVPN

O arquivo precisa usar o formato CSV com os registros `HEADER`,
`CLIENT_LIST`, `ROUTING_TABLE` e `END`. Uma configuração típica é:

```text
status /var/log/openvpn/openvpn-status.log
status-version 2
```

A aplicação retorna `503 Service Unavailable` até conseguir ler um snapshot
completo.

## Produção com systemd

Os arquivos de implantação ficam em `deploy/`:

- `openvpn-monitor.service`: unidade base para systemd;
- `openvpn-monitor.env.example`: configuração inicial;
- `install.sh`: instala a aplicação, virtualenv e serviço.

Em Ubuntu, instale primeiro o suporte a virtualenv se necessário:

```bash
sudo apt-get install python3-venv
```

Depois revise `deploy/openvpn-monitor.env.example` e execute, a partir do
repositório:

```bash
sudo ./deploy/install.sh
```

O instalador:

1. copia a aplicação para `/opt/openvpn-monitor-fast`;
2. cria `/opt/openvpn-monitor-fast/.venv`;
3. instala as dependências de `requirements.txt`;
4. cria `/etc/default/openvpn-monitor` somente se ele ainda não existir;
5. instala e inicia `openvpn-monitor.service`.

O instalador preserva um `/etc/default/openvpn-monitor` existente e não altera
a configuração do OpenVPN. O bind padrão é `127.0.0.1:8081`. Defina um
endereço apropriado no arquivo de ambiente quando o acesso pela rede for
necessário.

A unidade executa como `root` para conseguir ler instalações cujo arquivo de
status tem permissões restritas. Para aplicar privilégio mínimo, torne o
status legível por um usuário ou grupo dedicado e ajuste `User` e `Group` na
unidade.

Configuração de referência:

```text
Aplicação: /opt/openvpn-monitor-fast/openvpn_monitor_fast.py
Status:    /var/log/openvpn/openvpn-status.log
URL:       http://127.0.0.1:8081/
```

Comandos de operação:

```bash
sudo systemctl status openvpn-monitor.service
sudo journalctl -u openvpn-monitor.service
sudo systemctl restart openvpn-monitor.service
```

## Endpoints

| Requisição | Resposta |
| --- | --- |
| `GET /` | Página HTML |
| `HEAD /` | Cabeçalhos da página |
| `GET /?get_json=1` | JSON legado |
| `GET /healthz` | Saúde, quantidade de clientes e idade do snapshot |

Métodos diferentes de `GET` e `HEAD` retornam `405 Method Not Allowed`.

## Validação

```bash
python3 -m py_compile openvpn_monitor_fast.py
bash -n deploy/install.sh
# Após a instalação:
sudo systemd-analyze verify /etc/systemd/system/openvpn-monitor.service
```

## Código legado

A implementação anterior está preservada na branch `legacy`.

## Licença

Este projeto é distribuído sob a GNU General Public License versão 3. Consulte
`COPYING`.
