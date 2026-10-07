# io-guard

In-process IO Sanitizer and Guard for Claude Code and AI Harness.

## O que faz

1. **Truncamento inteligente em memoria**: trunca saidas de ferramentas acima de 150 linhas preservando cabecalho e rodape (50 linhas iniciais e 50 finais). Preserva relatorios de testes automatizados ate 300 linhas.
2. **Redacao de segredos em memoria**: mascara chaves de API (OpenAI, Anthropic, GitHub PATs, AWS, Google AI), JWTs, strings de conexao com senha e chaves privadas antes de chegarem ao contexto do modelo.
3. **Guardrail de escrita (Regra 875)**: intercepta execucao de comandos no terminal (`git commit`, `git push`) e bloqueia violacoes de travessao, emojis e aspas tipograficas.
4. **Protecao de branches protegidas**: consulta `targets.yaml` e bloqueia comandos `git push --force` ou pushes direcionados para branches de protecao (`main`, `master`, `develop`).
5. **Comando slash `/cleanwriting`**: higieniza rapidamente qualquer texto fornecido como argumento.

## Estrutura

- `.claude-plugin/`: Manifesto do plugin Claude Code e definicao de marketplace.
- `hooks/`: Registrador de eventos `tool.call`, `session.start` e `command.run`.
- `test/`: Testes unitarios executados com Bun (`bun test`).

## Validacao

```bash
bun test
claude plugin validate .
```
