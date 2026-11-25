# Divulgação de vulnerabilidades de segurança

Este arquivo descreve o processo de divulgação de vulnerabilidades deste repositório de plugin (id `ssh-guard`); não é um documento de projeto de segurança.

## Escopo

Abrange: a implementação de `SSH 加固插件` (id `ssh-guard`), a declaração de capacidades em `info.json`, o front-end `web/` e os artefatos de `make dist`.

Não abrange: problemas do núcleo e do protocolo — relate-os conforme o [SECURITY.md do kore](https://github.com/kore-pl/kore/blob/main/SECURITY.md); vulnerabilidades conhecidas em dependências de terceiros também devem ser relatadas ao projeto upstream.

## Versões suportadas

| Versão | Estado | Observação |
| --- | --- | --- |
| `0.4.0` (mais recente) | ✅ Aceita e corrigida | Correções de segurança são fornecidas apenas para a versão de patch mais recente |
| Versões `0.x` anteriores | ❌ Sem suporte | Atualize antes para a versão mais recente |

Durante `0.x`, o suporte é mínimo: apenas o patch mais recente de uma linha minor recebe correções; patches antigos não são retroportados.

## Superfície de ataque deste repositório

- **Métodos RPC**: todos os métodos `ssh-guard.*` (veja `README.md`); a falta de validação de parâmetros pode causar escalada de privilégios ou injeção.
- **capabilities**: `info.json.capabilities` é a superfície completa de autorização do plugin; cada declaração extra é outro vetor de ataque.
- **Processo separado e UDS**: o plugin roda como processo separado; o socket é criado pelo shell anfitrião, `chown kore-<id>`, modo `0600`; burlar permissões do socket ou conectar-se ao socket de outro plugin é uma vulnerabilidade.
- **Superfície de escrita no host**: qualquer escrita fora das capabilities efetivamente concedidas (arquivos / processos / rede / banco de dados) é uma vulnerabilidade.
- **Front-end**: `web/` roda em um iframe de origem separada e se comunica com o shell via postMessage; XSS, falsificação de mensagens e leitura de dados de outros plugins são problemas de fronteira de segurança.

## Como relatar

1. **Prefira um Security Advisory do GitHub**: página de Security deste repositório → "Report a vulnerability" (canal privado, sem issue público).
2. **E-mail alternativo**: `pengtang1024@users.noreply.github.com`, assunto `[kore security] ssh-guard`.
3. **Não abra issues públicos nem cole PoCs em discussões ou PR.**
4. Inclua: versão afetada, passos de reprodução ou PoC, avaliação de impacto, se já é pública e preferência de crédito.

## Prazos e divulgação

- Confirme o recebimento e dê uma primeira avaliação em até **72 horas**; casos complexos recebem um plano depois.
- Coordene a divulgação após a correção, com janela padrão de **90 dias**; consulte antes se o problema estiver sendo explorado ativamente.
- Registre as correções de segurança no `CHANGELOG.md` após o lançamento (sem detalhes de exploração) e publique um aviso de segurança se necessário.

## Agradecimentos

O crédito é dado nas notas de lançamento com o consentimento do relatante; anônimo mediante solicitação.
