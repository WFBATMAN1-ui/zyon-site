# Vigia

Aplicação de monitorização de preços com interface web, API Node.js e base de dados SQLite.

## Teste gratuito no Render

O Blueprint `render.yaml` cria um web service gratuito e inicia o servidor com Node.js. Não é necessário instalar dependências externas.

1. Liga este repositório ao Render e cria o Blueprint a partir de `render.yaml`.
2. Depois do primeiro deploy, copia o endereço `https://...onrender.com` para a variável `PUBLIC_ORIGIN` nas definições do serviço e faz novo deploy.
3. Abre o endereço do serviço e cria a primeira conta. Por predefinição, apenas a primeira conta pode ser criada.

Este modo gratuito serve para demonstração. O serviço pode adormecer após 15 minutos sem tráfego e demora um pouco a acordar. A base SQLite fica em armazenamento temporário; os dados podem desaparecer quando a instância reiniciar ou for publicada de novo. Não uses esta configuração para guardar dados importantes. Render só disponibiliza disco persistente em serviços pagos.

As variáveis opcionais `TELEGRAM_BOT_TOKEN`, `DISCORD_WEBHOOK_URL`, `RESEND_API_KEY` e `MAIL_FROM` ficam vazias até serem configuradas no Render. Não coloques chaves nem o ficheiro `.env` no GitHub.

## Execução local

Requer Node.js 24.15 ou posterior. Copia `.env.example` para `.env` e inicia com `node server.js`; depois abre `http://localhost:3000`. `.env`, `.data` e os ficheiros SQLite estão excluídos do Git.

A aplicação inclui conta com sessão segura no servidor, produtos, verificações agendadas, histórico, alertas no painel e integrações opcionais de notificação. As verificações dependem das páginas de cada loja; algumas lojas exigem APIs oficiais. O checkout continua a ser feito na loja.