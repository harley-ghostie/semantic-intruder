# Semantic Intruder V2 — guia de uso

Extensão para automatizar testes de API a partir de uma requisição já capturada no Burp Suite. Você escolhe um campo e seu significado; a extensão gera testes direcionados, envia pelo Burp e organiza as respostas para revisão. Não é necessário escrever Java nem compilar para usar o JAR entregue.

Versão desta entrega: **0.2.0**. Construída para **Burp Suite Professional 2026.7.3**, usando **Montoya API 2026.7** e bytecode Java 21. Compilação e testes offline foram executados; o carregamento e a interface ainda precisam ser conferidos dentro da sua instalação do Burp.

## Instalar

1. No Burp, abra **Extensions → Installed → Add**.
2. Em **Extension type**, escolha **Java**.
3. Selecione **semantic-intruder-v2.jar**, entregue junto deste guia, e avance em **Next**.
4. Confira a mensagem de carregamento em **Output** e a nova aba **Semantic V2**.

Use o JAR da entrega ou o JAR dentro do ZIP. A pasta de código-fonte e o `pom.xml` são para manutenção futura; você não precisa abri-los para usar a extensão.

## Sua primeira execução

1. Escolha uma requisição válida no **Repeater** ou em **Proxy → HTTP history**. Confirme que a resposta original representa o cenário esperado.
2. Inclua o endpoint e os caminhos necessários em **Target → Scope**. A extensão verifica o escopo na prévia e imediatamente antes de cada envio.
3. Clique com o botão direito na requisição e escolha **Extensions → Enviar para Semantic V2**. Abra a aba **Semantic V2**. Se houver várias linhas selecionadas, será usada a primeira; em um editor, será usada a requisição daquele editor.
4. Em **Campo a testar**, selecione a ocorrência exata: query, segmento de path, campo JSON, form ou header. Campos repetidos de query/form aparecem com índices diferentes.
5. Confira **Significado**: Identificador, Texto, Número ou Booleano. A sugestão usa nome/tipo/valor e pode ser corrigida por você.
6. Para autorização, escolha **Identificador** e informe **um ID alternativo de teste por linha**, sem aspas. O ID pode ser de outra conta de teste cujo acesso pela sessão original deva ser negado. A extensão mantém a sessão original.
7. Marque ou desmarque **Incluir validação de entrada e tipos**. Desmarcar permite executar somente a massa alternativa.
8. Clique em **Gerar prévia**. Confira cada valor e o número máximo de envios. Gerar a prévia não envia requisições.
9. Clique em **Executar prévia**. Selecione uma linha nos resultados para comparar request/response com as abas de baseline.

Uma rodada executa **duas requisições originais de referência, os testes e uma referência final**. A extensão interrompe se as duas referências iniciais diferirem. Se só campos como `timestamp` ou `requestId` variarem, você pode informar seus JSON Pointers em **Ignorar campos dinâmicos**, por exemplo `/timestamp,/meta/requestId`, e gerar outra prévia. Não ignore os campos de identidade, propriedade ou conteúdo que você está avaliando. A lista usa vírgula como separador; chaves que contenham vírgula não podem ser informadas nessa configuração.

O intervalo padrão é de 500 ms após uma resposta até o próximo envio, com uma requisição por vez e até 50 testes + 3 referências. O tempo mostrado na coluna **ms** é o tempo de transporte observado pela extensão, sem o intervalo configurado; não é evidência suficiente para diagnóstico de falha por tempo.

## Como interpretar

- **2xx com ID alternativo:** revisar a autorização. Confirme que o recurso pertence à massa alternativa, que a sessão original não deveria acessá-lo e que não é apenas reflexão do identificador. O resultado não confirma IDOR automaticamente.
- **401/403:** acesso recusado; confira se a negativa ocorreu pela regra esperada. Um 401 interrompe a rodada para permitir revisão da sessão.
- **404:** pode significar recurso ausente ou ocultação do recurso; permanece inconclusivo.
- **4xx em validação:** entrada recusada; confirme o contrato esperado e a mensagem de erro.
- **2xx em validação:** entrada aceita; confira o contrato e o efeito. Aceitar Unicode ou um limite numérico pode ser comportamento correto.
- **5xx:** sinal para investigação; não é automaticamente uma vulnerabilidade confirmada.
- **3xx:** redirecionamento registrado, sem seguir o destino.
- **Baseline final diferente:** os resultados da rodada são inconclusivos até revisar sessão/estado. A mensagem geral também é preservada na exportação.

O comparador verifica status, tamanho, igualdade do corpo e diferenças por JSON Pointer (até 30 caminhos exibidos). Ordem das chaves de objetos JSON não gera diferença. Para corpos sem JSON válido, usa comparação exata. Headers completos ficam disponíveis no editor de evidências, sem classificação automática por header.

## Escrita e parada

Para métodos diferentes de GET, HEAD e OPTIONS, marque **Incluir esta requisição de escrita** antes da prévia. Isso significa repetir a operação original nos três baselines e em cada teste. A classificação por método não garante ausência de efeitos: um GET também pode ter efeitos conforme a aplicação. Escolha uma massa apropriada para o comportamento da operação.

**Parar** interrompe o agendamento dos próximos envios. A requisição que já foi enviada pode concluir; o timeout configurado é de 30 segundos. Importar outra requisição fica bloqueado enquanto a execução termina. Falta de resposta, saída do escopo, resposta maior que 2 MB, 401 ou 429 interrompem a rodada. Uma rodada interrompida mantém resultados parciais, sem validação final completa.

## x-charon e x-charon-params

A extensão identifica objetos/listas JSON literais e Base64/Base64url de JSON UTF-8, mostrando seus campos internos. Ela preserva os outros valores do objeto, mas reserializa o JSON; espaços e a grafia numérica podem mudar. O padding de Base64 é preservado quando presente. Se o alfabeto de entrada for ambíguo entre Base64 padrão e Base64url, o parser prioriza Base64 padrão.

Conteúdo opaco, criptografado ou em formato desconhecido não recebe edição interna. A extensão **não recalcula assinaturas, HMACs ou checksums**. Se o header real usar um desses formatos, precisamos de sua estrutura sanitizada para implementar o codec correto.

## Experimentar com dados fictícios

O laboratório fornecido é opcional e usa somente a biblioteca padrão do **Python 3**. Ele escuta apenas em `127.0.0.1:8765` e não armazena alterações.

1. Extraia o ZIP inteiro.
2. No Linux/macOS, abra um terminal na pasta extraída e execute `sh INICIAR-LAB.sh`. No Windows com Python instalado, abra `INICIAR-LAB.cmd`. Mantenha a janela aberta.
3. Inclua `http://127.0.0.1:8765/` no Target scope do Burp.
4. No Repeater, crie uma requisição com destino **HTTP**, host **127.0.0.1**, porta **8765**. Copie uma requisição por vez de `exemplos-lab.http`, sem as linhas de comentário `###`.
5. Envie o exemplo `/vulnerable/cards?cardId=A100` uma vez para conferir a resposta.
6. Envie a requisição para **Semantic V2**, escolha **QUERY · cardId [0]**, selecione **Identificador**, informe `B200` e desmarque validação de entrada.
7. Gere a prévia e execute. São quatro envios: dois baselines, um teste e o baseline final. O teste retorna `owner: user-B`, pois esse endpoint do laboratório tem uma falha intencional.
8. Repita com `/protected/cards?cardId=A100`: o mesmo teste com `B200` retorna 403.
9. Use `/charon/cards` para experimentar seleção de `/cardId` dentro do header e `/validate` para testes JSON de números, booleanos e texto. O POST de validação não persiste dados nesse laboratório, mas ainda exige habilitar escrita na extensão.
10. Encerre o laboratório com **Ctrl+C**.

Token e identificadores do laboratório são fictícios: `Bearer demo-A`, `A100` e `B200`. Os baselines são estáveis para facilitar a primeira experiência.

## Exportação e dados

**Exportar metadados JSON** salva status HTTP, tamanho, tempo, classificação, caminhos JSON alterados, SHA-256 do corpo e o estado final da rodada. Não inclui URLs, headers, corpos completos nem valores dos payloads. Nomes de campos em JSON Pointers podem revelar características do esquema e fazem parte do relatório.

As requisições e respostas completas permanecem disponíveis nos editores da extensão durante a sessão. **Limpar requisição e resultados** remove as referências da interface; isso não apaga registros que o próprio Burp tenha mantido. A extensão não grava configurações, tokens ou tráfego automaticamente em arquivos e não envia informações para serviços de IA. O transporte usa o Burp, portanto configurações e outras extensões da sua instalação podem influenciar a requisição efetivamente enviada; confira a request retornada nas evidências.

## Escopo desta entrega e limites

Disponível: interface em português, importação pelo menu de contexto, sugestão semântica editável, prévia, execução sequencial, campos aninhados JSON/arrays, query/form com ocorrências repetidas, segmentos de path, headers simples, JSON dentro de x-charon, limites de entrada/tipo, massa alternativa de IDs, comparações e exportação de metadados.

Não incluído: troca automática entre sessões A/B, renovação de tokens, mapeamento automático de proprietário, inferência por IA, scanner de injeção, descoberta de endpoints, enumeração de IDs, recálculo de assinaturas, replay de fluxos com várias etapas, execução agendada e o módulo interno chamado de “path traversal”, cuja definição ainda falta.

JSON com chaves duplicadas, sintaxe não estrita, profundidade acima de 64 ou mais de 2.000 folhas é recusado. Corpos comprimidos, charset explícito diferente de UTF-8, multipart, XML e binários não oferecem seleção de campos do corpo. Headers de autenticação/roteamento/framing e headers duplicados são excluídos dos alvos. A requisição de entrada tem limite de 1 MB. Essas restrições aparecem na interface quando aplicáveis.

## Manutenção do código (opcional)

Com JDK 21+ e Maven 3.9+, dentro da pasta do projeto:

```sh
mvn clean verify
```

O JAR será criado em `target/semantic-intruder-v2.jar`. Gson é empacotado com namespace isolado; a Montoya API é fornecida pelo Burp e não é embutida. Testes cobrem parsing, seleção de campos, mutações, comparação e execução com transporte simulado. O relatório `VALIDACAO.md` registra as verificações desta entrega.

Referências oficiais consultadas: [criação de extensões](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating), [carregamento do JAR](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/loading-in-burp) e [Montoya API](https://github.com/PortSwigger/burp-extensions-montoya-api).
