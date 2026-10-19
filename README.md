# Vigia

O Vigia é uma aplicação web com uma interface de monitorização de preços, uma API Node.js, base de dados SQLite, sessão segura no servidor, verificações agendadas e canais opcionais de alerta.

## Executar no teu computador

1. Instala Node.js 24.15 ou posterior.
2. Abre PowerShell na pasta `outputs`.
3. Copia a configuração de exemplo e abre o ficheiro local:

   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```

4. Mantém `DATA_DIR=.data` e `PUBLIC_ORIGIN=http://localhost:3000`. Ajusta `STORE_ALLOWLIST` com os domínios das lojas que queres acompanhar. Guarda `.env`.
5. Inicia o servidor:

   ```powershell
   node server.js
   ```

6. Abre `http://localhost:3000` e cria a primeira conta. Usa uma palavra-passe com pelo menos 12 caracteres. Por predefinição, o servidor aceita apenas a primeira conta; muda `ALLOW_SIGNUPS=true` se quiseres permitir inscrições públicas.
7. A base de dados e as sessões ficam em `.data/vigia.sqlite`. O ficheiro `.env` e a base de dados estão excluídos do Git.

O servidor não precisa de `npm install`: usa módulos incluídos no Node.js. A base de dados usa `node:sqlite`, que está disponível a partir do Node 22.5 e é Release Candidate no Node 24.15+. Para esta primeira versão, o SQLite serve uma instância única e uma utilização pequena. Uma versão com várias instâncias deve migrar para PostgreSQL.

## O que funciona

- Criação da primeira conta, início e fim de sessão com cookie `HttpOnly`, limite de tentativas e palavra-passe derivada com `scrypt`.
- Reset de palavra-passe por email quando a integração Resend está configurada.
- Produtos guardados no servidor: adicionar, editar, pausar, retomar e remover.
- Verificações manuais e agendadas, histórico de cada preço observado, alertas e preferências guardados na base de dados.
- Histórico de preços filtrável por produto e período, com comparação visual ao preço-alvo.
- Leitura de preço e disponibilidade a partir de dados estruturados Schema.org/JSON-LD ou metadados de produto.
- Alertas de preço e reposição de stock no painel, Telegram e Discord.
- Exportação CSV no dashboard.

O Vigia abre a página da loja a partir de cada produto. Esta versão não guarda meios de pagamento nem conclui compras automaticamente; o checkout é feito na loja.

## Ligar Telegram

1. No Telegram, abre `@BotFather`, envia `/newbot` e segue os passos. Copia o token para `TELEGRAM_BOT_TOKEN` no `.env`.
2. Reinicia o servidor.
3. Abre o bot novo e envia `/start`.
4. No Vigia, abre **Definições** e carrega em **Ligar** ao lado de Telegram. A aplicação associa o chat privado à tua conta; depois carrega em **Testar**.

O token só existe no servidor. Não o coloques no browser, no GitHub ou nesta conversa. O Vigia usa `getUpdates` para encontrar o `/start`; não configures um webhook de entrada nesse bot.

## Ligar Discord

1. No teu servidor Discord, abre **Server Settings → Integrations → Create Webhook**.
2. Escolhe o canal de alertas e copia a URL do webhook.
3. Guarda-a em `DISCORD_WEBHOOK_URL` no `.env` e reinicia o servidor.
4. No Vigia, abre **Definições** e carrega em **Testar** ao lado de Discord.

A URL do webhook dá acesso de publicação ao canal. Mantém-na privada e troca-a no Discord se for exposta.

## Ligar email de recuperação

1. Cria uma conta Resend e verifica um domínio/remetente para envio.
2. Guarda a chave em `RESEND_API_KEY` e o remetente validado em `MAIL_FROM`.
3. Define `PUBLIC_ORIGIN` como o endereço real da aplicação e reinicia/deploya o servidor.
4. Usa **Esqueceste-te?** no ecrã de login para pedir um link de recuperação de uma hora.

Sem estas três variáveis (`RESEND_API_KEY`, `MAIL_FROM` e `PUBLIC_ORIGIN`), o formulário não consegue entregar emails.

## Lojas e monitorização

`STORE_ALLOWLIST` é uma lista de domínios permitidos, por exemplo `amazon.es,fnac.pt,nike.com`. O servidor só abre páginas HTTPS de domínios dessa lista, valida os endereços DNS públicos, respeita regras básicas de `robots.txt`, limita páginas a 2 MB, timeout de 12 segundos e pelo menos um minuto entre pedidos à mesma loja. Não usa rotação de proxies nem tenta contornar bloqueios.

Muitas lojas constroem o preço no browser ou limitam pedidos automáticos. Nessas lojas, é necessário ligar uma API/feed oficial ou criar um adaptador específico; a verificação mostra o motivo no servidor em vez de inventar um preço. Tarifas aéreas normalmente precisam de uma API de viagens própria, com chave e limites do fornecedor.

## Publicar online com Render

O ficheiro `render.yaml` está preparado para um serviço web Node e um disco persistente SQLite. Mantém o ficheiro na raiz do repositório que ligares ao Render.

1. Cria um repositório privado GitHub e coloca nele os ficheiros desta pasta.
2. No Render, cria uma **Blueprint** a partir desse repositório e revê os serviços e custos apresentados antes de confirmar. O serviço precisa de um disco persistente para a base de dados não desaparecer num deploy; o disco persistente requer um plano pago no Render.
3. Quando a aplicação ganhar o endereço `https://...onrender.com`, define `PUBLIC_ORIGIN` com esse endereço no Environment do serviço.
4. Na mesma página, introduz os tokens que tiveres: `TELEGRAM_BOT_TOKEN`, `DISCORD_WEBHOOK_URL`, `RESEND_API_KEY` e `MAIL_FROM`. Não os guardes no repositório.
5. Guarda e espera pelo deploy. Abre a URL, cria a conta e testa uma integração.
6. Um domínio próprio é opcional; o endereço `onrender.com` chega para começar.

O Render usa o sistema de ficheiros efémero por predefinição. O Blueprint associa o disco em `/var/data`, e `DATA_DIR` aponta a base de dados para esse caminho.

## O que preciso de ti para ligar serviços reais

Manda estes dados, sem chaves secretas:

- As lojas e domínios exatos que queres primeiro.
- Se preferes começar por Telegram, Discord, ambos ou email.
- Se já tens GitHub, conta Render e domínio próprio; indica também o teto mensal que aceitas para alojamento.
- Se a conta será apenas tua ou se outras pessoas também vão entrar.
- Se tens acesso a APIs/feed oficiais das lojas escolhidas; diz o nome do fornecedor, nunca a chave.

As chaves ficam no `.env` local durante o desenvolvimento e nos **Environment Variables** do alojamento em produção. Não envies tokens, palavras-passe, dados de cartão ou credenciais de loja por chat.
