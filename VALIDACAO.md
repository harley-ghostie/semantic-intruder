# Verificação da entrega — 09/09/2026

**Resultado:** JAR compilado; 37 testes Java aprovados, sem falhas ou testes ignorados; 12 verificações HTTP no laboratório local aprovadas.

## Ambiente de construção

- Eclipse Temurin JDK 21.0.12.1, Linux x86_64.
- Maven 3.9.11.
- Montoya API 2026.7, fornecida pelo Burp em runtime.
- Gson 2.13.2, incluído no JAR sob namespace privado.
- JUnit Jupiter 5.13.4 para testes.
- Comando de construção do projeto: `mvn package` (com repositório Maven local isolado no ambiente de trabalho).

## Testes Java

- **16 testes de semântica:** distinção entre famílias de teste, IDs explicitamente fornecidos, tipos JSON e zeros à esquerda, limite de casos, parsing estrito, chaves duplicadas, profundidade, JSON Pointer, Unicode/encoding, comparação de campos dinâmicos, status inconclusivos e ausência de confirmação automática de IDOR.
- **10 testes de seleção/mutação:** segmentos de path, query/form com chaves repetidas, campos JSON aninhados, formatos x-charon, preservação de demais campos, exclusão de autenticação/framing, rejeição de quebra de linha em header e restrições de charset/compressão.
- **11 testes de execução com transporte simulado:** sequência de baselines e testes, baseline inicial inválido, instabilidade, campos dinâmicos, revisão de escopo antes de cada envio, parada, 401/429, mudança de baseline final, ausência de resposta, limite de resposta, intervalo entre envios e rejeição de planos inconsistentes.

## Verificação HTTP do laboratório

Servidor iniciado temporariamente em loopback e porta livre, encerrado após as verificações. Conferidos: health, baseline A, negativa protegida para B, acesso intencionalmente vulnerável a B, ID inexistente, sessão inválida, x-charon JSON, x-charon Base64, JSON válido, recusa de booleano como número, recusa de string como booleano e limite de comprimento de texto.

Nenhum teste foi enviado a endpoints de trabalho ou serviços de terceiros.

## Limites desta validação

Os testes Java usam doubles da Montoya API e transporte simulado; não exercitam a implementação interna do Burp. A compilação verifica as assinaturas da API, mas não substitui o teste de carregamento do JAR e do fluxo visual no **Burp Professional 2026.7.3**. A interface Swing e o envio integrado ainda precisam dessa validação na instalação da usuária.

O laboratório valida cenários sintéticos. A interpretação de autorização em uma API real continua dependendo da política de acesso, das contas e da propriedade dos recursos de teste.
