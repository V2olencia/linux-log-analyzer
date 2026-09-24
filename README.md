# Linux Log Analyzer

Analisador educacional de logs de autenticação Linux feito somente com a biblioteca padrão do Python. O objetivo é praticar Linux, expressões regulares, agregação de eventos e triagem inicial de segurança.

## O que o projeto detecta

- falhas de login por SSH;
- logins SSH aceitos;
- falhas de autenticação com `sudo`;
- endereços IP com falhas repetidas acima de um limiar configurável;
- usuários mais visados nas tentativas.

O arquivo de exemplo é totalmente sintético e usa blocos de IP reservados para documentação.

## Executar

Requisito: Python 3.10 ou superior.

```bash
python3 log_analyzer.py sample_logs/auth.log
python3 log_analyzer.py sample_logs/auth.log --threshold 3
python3 log_analyzer.py sample_logs/auth.log --json
```

## Testes

```bash
python3 -m unittest discover -s tests -v
```

## Como funciona

1. cada linha é comparada com padrões explícitos de SSH e `sudo`;
2. endereços IP são validados com `ipaddress`;
3. eventos reconhecidos são contados por tipo, IP e usuário;
4. um alerta é criado quando um IP atinge o limiar de falhas.

## Limitações honestas

- suporta apenas três formatos documentados de eventos;
- distribuições Linux podem produzir mensagens diferentes;
- o alerta é baseado em contagem, sem janela de tempo;
- não correlaciona hosts, geolocalização ou inteligência de ameaças;
- não substitui SIEM, EDR nem uma investigação humana.

## Privacidade e uso responsável

Logs reais podem conter nomes de usuário, IPs, nomes de host e outros dados sensíveis. Antes de compartilhar um exemplo, substitua esses campos por valores fictícios. Não publique tokens, chaves, senhas nem logs de terceiros.

## Próximos passos

- reconhecer timestamps e calcular janelas de tempo;
- adicionar suporte configurável para outros formatos;
- exportar CSV;
- documentar uma análise manual comparativa com `grep`, `awk` e `journalctl`.
