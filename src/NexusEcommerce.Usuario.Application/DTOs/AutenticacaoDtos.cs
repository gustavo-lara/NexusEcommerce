// Namespace que agrupa DTOs de autenticação
// DTOs = Data Transfer Objects (estruturas para transferir dados entre camadas)
namespace NexusEcommerce.Usuario.Application.DTOs;

/// <summary>
/// Resposta retornada ao cliente após um login bem-sucedido.
/// 
/// Este DTO encapsula todos os dados necessários para o cliente começar a usar a API:
/// - O access token (JWT) para autorizar requisições
/// - O refresh token para renovar o access token quando expirar
/// - Informações do usuário (nome e role)
/// - Quando o access token vai expirar
/// 
/// IMPORTANTE: Este é um DTO, não uma Entity
/// - Não tem ID (não é persistido no banco)
/// - Não tem métodos de negócio
/// - Apenas transfere dados entre cliente e servidor
/// - Pode ser serializado para JSON automaticamente
/// 
/// Por que um record?
/// - `record` é ideal para DTOs (imutável, conciso, sem boilerplate)
/// - Desde C# 9, records são a forma recomendada
/// - Propriedades são read-only por padrão
/// - Equals() e GetHashCode() são gerados automaticamente
/// 
/// Exemplo de uso:
/// 
/// var response = new LoginResponseDto(
///     AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///     RefreshToken: "v/bKa5f8nM2pQ9xL7wS4rT1u3vY6zX8B...",
///     ExpiracaoAccessToken: DateTime.UtcNow.AddMinutes(60),
///     Usuario: "João Silva",
///     Role: "Cliente"
/// );
/// 
/// // Serializado para JSON automaticamente:
/// // {
/// //   "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
/// //   "refreshToken": "v/bKa5f8nM2pQ9xL7wS4rT1u3vY6zX8B...",
/// //   "expiracaoAccessToken": "2025-04-13T16:45:00Z",
/// //   "usuario": "João Silva",
/// //   "role": "Cliente"
/// // }
/// 
/// </summary>
public record LoginResponseDto(
    /// <summary>
    /// Token JWT (JSON Web Token) para autorizar requisições.
    /// 
    /// O que é JWT?
    /// - Um token criptografado que contém informações do usuário
    /// - Enviado pelo cliente em cada requisição no header Authorization
    /// - Exemplo: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    /// 
    /// Estrutura de um JWT:
    /// header.payload.signature
    /// 
    /// header: Diz que é JWT e qual algoritmo de criptografia usa
    /// payload: Contém as informações (claims):
    ///   - sub (subject): ID do usuário
    ///   - email: Email do usuário
    ///   - role: Papel do usuário
    ///   - iat (issued at): Quando foi gerado
    ///   - exp (expiration): Quando expira
    /// signature: Garante que o token não foi alterado
    /// 
    /// Fluxo:
    /// 1. Cliente recebe JWT após login
    /// 2. Cliente armazena no navegador (localStorage, sessionStorage)
    /// 3. Cliente envia JWT em cada requisição
    /// 4. Servidor valida JWT (checa assinatura, issuer, audience, expiration)
    /// 5. Se válido, processa a requisição
    /// 6. Se inválido, retorna 401 Unauthorized
    /// 
    /// Segurança:
    /// - JWT não contém senha
    /// - JWT é criptografado mas pode ser decodificado (não é privado)
    /// - A segurança vem da assinatura (só o servidor pode assinar)
    /// - Se alguém interceptar o JWT, pode ver os dados mas não pode alterar
    /// - É por isso que usamos HTTPS
    /// 
    /// Tempo de vida (TTL):
    /// - Geralmente 60 minutos (curto para segurança)
    /// - Se expirar, cliente usa refresh token para gerar novo
    /// </summary>
    string AccessToken,

    /// <summary>
    /// Token de atualização para renovar o access token.
    /// 
    /// O que é Refresh Token?
    /// - Um token muito maior (aleatório, 32 bytes em Base64 = 44 caracteres)
    /// - Armazenado no banco de dados (não é um JWT)
    /// - Usado apenas para gerar novo access token
    /// - NUNCA deve ser enviado a requisições normais (apenas /api/auth/refresh-token)
    /// 
    /// Por que precisamos?
    /// - Se access token durasse 7 dias, seria muito inseguro (muito tempo exposto)
    /// - Mas pedir login a cada 60 minutos é ruim para UX
    /// - Solução: access token curto (60 min) + refresh token longo (7 dias)
    /// - Quando access token expira, cliente pede novo access token com refresh token
    /// 
    /// Fluxo:
    /// 1. Cliente faz login
    /// 2. Recebe access token (60 min) + refresh token (7 dias)
    /// 3. Usa access token para requisições
    /// 4. Quando access token expira (60 min depois)
    /// 5. Cliente recebe 401 Unauthorized
    /// 6. Cliente envia refresh token para /api/auth/refresh-token
    /// 7. Servidor gera novo access token (e novo refresh token)
    /// 8. Cliente continua com novo access token (outro 60 min)
    /// 9. Processo se repete até refresh token expirar (7 dias)
    /// 
    /// Armazenamento:
    /// - O cliente armazena em localStorage ou memory
    /// - IMPORTANTE: NUNCA localStorage para refresh token (XSS vulnerability)
    /// - Melhor: sessionStorage (limpo ao fechar navegador) ou memory (React/Vue state)
    /// - Melhor ainda: HttpOnly Cookie (não acessível via JavaScript)
    /// 
    /// Segurança:
    /// - Cada refresh token é único (aleatório)
    /// - Armazenado no banco (pode ser revogado no logout)
    /// - Se interceptado, pode ser usado, mas por pouco tempo
    /// - Cada refresh token só funciona uma vez (usou = revogado e novo criado)
    /// </summary>
    string RefreshToken,

    /// <summary>
    /// Data e hora quando o access token vai expirar.
    /// 
    /// Tipo: DateTime em UTC (sem fuso horário local)
    /// Exemplo: "2025-04-13T16:45:00Z"
    /// 
    /// Por que enviar para o cliente?
    /// - O cliente precisa saber quando deve fazer refresh
    /// - Protocolo: se atual > ExpiracaoAccessToken, pede novo
    /// 
    /// Cálculo:
    /// DateTime.UtcNow.AddMinutes(60)
    /// - UtcNow: agora em UTC
    /// - AddMinutes(60): adiciona 60 minutos
    /// 
    /// Exemplo:
    /// - Login às 14:30 UTC
    /// - ExpiracaoAccessToken = 15:30 UTC
    /// - Em 14:50, ainda é válido (faltam 40 minutos)
    /// - Em 15:30, expirou (precisa refresh)
    /// - Em 15:35, expirou (precisa refresh)
    /// 
    /// Validação no servidor:
    /// if (token.exp < DateTime.UtcNow)
    /// {
    ///     // Token expirou, retorna 401
    /// }
    /// </summary>
    DateTime ExpiracaoAccessToken,

    /// <summary>
    /// Nome do usuário que fez login.
    /// 
    /// Tipo: string
    /// Origem: Cliente.NomeCompleto
    /// 
    /// Função: Exibição na UI
    /// Exemplo: "João Silva"
    /// 
    /// Segurança: Dado público, pode ser enviado
    /// 
    /// Uso típico no frontend:
    /// <h1>Bem-vindo, {response.usuario}!</h1>
    /// </summary>
    string Usuario,

    /// <summary>
    /// Papel (role) do usuário no sistema.
    /// 
    /// Tipo: string
    /// Valores possíveis: "Cliente", "Moderador", "Administrador"
    /// 
    /// Origem: UserRole.ToString() (converte enum para string)
    /// Exemplo: UserRole.Moderador.ToString() = "Moderador"
    /// 
    /// Função: Informar o frontend sobre permissões
    /// 
    /// Uso no frontend:
    /// if (response.role == "Administrador")
    /// {
    ///     mostrarMenuAdmin();
    /// }
    /// 
    /// Segurança:
    /// - O role também vem no JWT (claims)
    /// - Este é apenas para conveniência (não precisa decodificar JWT)
    /// - Não confia apenas nisto! O servidor deve validar no JWT também!
    /// - Um usuário malicioso pode alterar isto no localStorage
    /// - O servidor SEMPRE valida o JWT no header Authorization
    /// </summary>
    string Role
);

/// <summary>
/// Resposta retornada ao cliente após renovação bem-sucedida de access token.
/// 
/// Fluxo:
/// 1. Cliente faz requisição com access token expirado
/// 2. Recebe 401 Unauthorized
/// 3. Cliente envia refresh token para /api/auth/refresh-token
/// 4. Servidor valida refresh token
/// 5. Se OK, gera novo access token e novo refresh token
/// 6. Retorna RefreshTokenResponseDto
/// 7. Cliente armazena novos tokens
/// 8. Cliente retenta requisição original com novo access token
/// 
/// Por que novo refresh token também?
/// - Segurança: cada refresh token só funciona uma vez
/// - Se não gerasse novo, o antigo seria inútil depois da primeira renovação
/// - Permite rastreamento de quantas vezes renovou (auditoria)
/// 
/// Exemplo de uso:
/// 
/// var response = new RefreshTokenResponseDto(
///     NovoAccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///     NovoRefreshToken: "a9B8c7D6e5F4g3H2i1J0k9L8m7N6o5P...",
///     ExpiracaoAccessToken: DateTime.UtcNow.AddMinutes(60)
/// );
/// 
/// </summary>
public record RefreshTokenResponseDto(
    /// <summary>
    /// Novo JWT gerado após renovação bem-sucedida.
    /// 
    /// Tipo: string
    /// Formato: JWT padrão
    /// TTL: 60 minutos a partir de agora
    /// 
    /// Diferença do login:
    /// - No login: LoginResponseDto tem AccessToken + RefreshToken + info do usuário
    /// - No refresh: RefreshTokenResponseDto tem apenas tokens
    /// - Não precisa enviar dados do usuário de novo
    /// 
    /// Armazenamento:
    /// // Pseudocódigo JavaScript/Frontend
    /// const response = await fetch('/api/auth/refresh-token', {
    ///     method: 'POST',
    ///     headers: { 'Authorization': `Bearer ${oldAccessToken}` }
    /// });
    /// const data = await response.json();
    /// 
    /// // Armazenar novo access token
    /// localStorage.setItem('accessToken', data.novoAccessToken);
    /// // NÃO armazenar refresh token em localStorage!
    /// // Preferir sessionStorage ou HttpOnly Cookie
    /// </summary>
    string NovoAccessToken,

    /// <summary>
    /// Novo refresh token gerado após renovação bem-sucedida.
    /// 
    /// Tipo: string
    /// Formato: Aleatório Base64 (não é JWT)
    /// TTL: 7 dias a partir de agora
    /// 
    /// Por que criar novo?
    /// - Revoga automaticamente o antigo (segurança)
    /// - Permite apenas uma renovação por refresh token
    /// - Se alguém roubar o refresh token, só pode usar uma vez
    /// - Depois, o sistema nota tentativa de usar refresh revogado
    /// 
    /// Armazenamento:
    /// // ERRADO: localStorage (vulnerável a XSS)
    /// localStorage.setItem('refreshToken', data.novoRefreshToken);
    /// 
    /// // MELHOR: sessionStorage (limpo ao fechar navegador)
    /// sessionStorage.setItem('refreshToken', data.novoRefreshToken);
    /// 
    /// // MELHOR AINDA: Memory em variável (React/Vue state)
    /// const [refreshToken, setRefreshToken] = useState(data.novoRefreshToken);
    /// 
    /// // MELHOR AINDA: HttpOnly Cookie (servidor gerencia)
    /// // Browser automaticamente envia em requisições
    /// // JavaScript não consegue acessar (seguro contra XSS)
    /// </summary>
    string NovoRefreshToken,

    /// <summary>
    /// Data e hora quando o novo access token vai expirar.
    /// 
    /// Tipo: DateTime em UTC
    /// Exemplo: "2025-04-13T17:45:00Z"
    /// 
    /// Cálculo: DateTime.UtcNow.AddMinutes(60)
    /// 
    /// Uso no frontend:
    /// // Pseudocódigo JavaScript
    /// const agora = new Date();
    /// const diferenca = new Date(data.expiracaoAccessToken) - agora;
    /// const minutosRestantes = diferenca / (1000 * 60);
    /// 
    /// console.log(`Access token expira em ${minutosRestantes} minutos`);
    /// 
    /// // Exemplo: se gerado agora, vai dizer "60 minutos"
    /// // Depois de 50 minutos, vai dizer "10 minutos"
    /// // Depois de 60 minutos, vai expirado
    /// </summary>
    DateTime ExpiracaoAccessToken
);

/// <summary>
/// Representa um usuário em uma listagem paginada.
/// 
/// Este DTO é usado na resposta de GET /api/auth/usuarios
/// 
/// Diferenças:
/// - UsuarioPaginadoDto: Para listagem (campos públicos apenas)
/// - ClienteResponseDto: Para perfil individual (mais completo)
/// - Cliente: Entity do domínio (não deve ser exposta diretamente)
/// 
/// Campos inclusos:
/// - Id: Para poder fazer outras ações (ex: edit, delete)
/// - NomeCompleto: Para identificação
/// - Email: Para contato
/// - Cpf: Para identificação legal (formatado, sem dígitos verificadores expostos)
/// - Role: Para saber o papel
/// - CriadoEm: Para auditoria (saber quanto tempo está no sistema)
/// 
/// Campos NÃO inclusos (segurança):
/// - Senha: NUNCA expor hash de senha
/// - IdentityId: Informação interna do ASP.NET Core Identity
/// - Endereço completo: Privado do usuário
/// - Dados sensíveis: CPF sem formatação, etc.
/// 
/// Exemplo de uso:
/// 
/// var usuarioPaginado = new UsuarioPaginadoDto(
///     Id: Guid.Parse("550e8400-e29b-41d4-a716-446655440000"),
///     NomeCompleto: "João Silva",
///     Email: "joao@example.com",
///     Cpf: "123.456.789-00",
///     Role: "Cliente",
///     CriadoEm: DateTime.Parse("2025-04-10T10:30:00Z")
/// );
/// 
/// // Serializado para JSON:
/// // {
/// //   "id": "550e8400-e29b-41d4-a716-446655440000",
/// //   "nomeCompleto": "João Silva",
/// //   "email": "joao@example.com",
/// //   "cpf": "123.456.789-00",
/// //   "role": "Cliente",
/// //   "criadoEm": "2025-04-10T10:30:00Z"
/// // }
/// 
/// </summary>
public record UsuarioPaginadoDto(
    /// <summary>
    /// ID único do cliente (Guid).
    /// 
    /// Tipo: Guid
    /// Origem: Cliente.Id
    /// 
    /// Função: Identificar o usuário
    /// Uso: Construir links (ex: /usuarios/550e8400...)
    /// Segurança: É um ID público (pode ser exposto)
    /// 
    /// Exemplo: "550e8400-e29b-41d4-a716-446655440000"
    /// 
    /// Formato JSON: uuid sem chaves
    /// </summary>
    Guid Id,

    /// <summary>
    /// Nome completo do usuário.
    /// 
    /// Tipo: string
    /// Origem: Cliente.NomeCompleto
    /// 
    /// Função: Identificação na listagem
    /// Exemplo: "João Silva"
    /// 
    /// Segurança: Dado público (pode ser exposto)
    /// </summary>
    string NomeCompleto,

    /// <summary>
    /// Email do usuário.
    /// 
    /// Tipo: string
    /// Origem: Cliente.Email
    /// 
    /// Função: Contato do usuário
    /// Exemplo: "joao@example.com"
    /// 
    /// Segurança: 
    /// - É público neste contexto (admin listando usuários)
    /// - Mas em contexto diferente, pode ser privado
    /// - Sempre verificar autorização no controller
    /// </summary>
    string Email,

    /// <summary>
    /// CPF formatado do usuário.
    /// 
    /// Tipo: string
    /// Origem: Cliente.Cpf.Numero (ou Cliente.Cpf.ObterFormatado())
    /// Formato: "123.456.789-00"
    /// 
    /// Função: Identificação legal
    /// 
    /// Segurança:
    /// - CPF é dado sensível (PII - Personally Identifiable Information)
    /// - Em GDPR/LGPD, é protegido
    /// - Exponha apenas quando necessário
    /// - Este DTO é usado apenas por admin/moderador
    /// - Controller deve validar autorização
    /// 
    /// Exemplo: "123.456.789-00"
    /// </summary>
    string Cpf,

    /// <summary>
    /// Papel (role) do usuário em formato string.
    /// 
    /// Tipo: string
    /// Origem: Cliente.Role.ToString()
    /// Valores: "Cliente", "Moderador", "Administrador"
    /// 
    /// Função: Mostrar na listagem qual é o papel
    /// 
    /// Exemplo: "Moderador"
    /// 
    /// Segurança: Informação pública (pode ser exposta)
    /// 
    /// Por que string e não enum?
    /// - JSON não tem enums, serializa como string ou int
    /// - Usando string é mais legível no JSON
    /// - Frontend não precisa conhecer o enum C#
    /// </summary>
    string Role,

    /// <summary>
    /// Data e hora quando o usuário foi criado.
    /// 
    /// Tipo: DateTime em UTC
    /// Origem: Data de criação no banco
    /// 
    /// Função: Auditoria e saber há quanto tempo está no sistema
    /// 
    /// Exemplo: "2025-04-10T10:30:00Z"
    /// 
    /// Segurança: Informação pública (pode ser exposta)
    /// 
    /// Uso:
    /// - Ordenar usuários (mais novo vs mais antigo)
    /// - Gerar relatórios (quantos usuários por dia)
    /// - Investigar fraudes (contas criadas na mesma hora)
    /// </summary>
    DateTime CriadoEm
);

/// <summary>
/// Resposta genérica para qualquer listagem paginada.
/// 
/// Este é um DTO GENÉRICO que pode ser usado para paginar qualquer tipo de dados.
/// 
/// Por que genérico?
/// - Paginação é um padrão comum em muitas APIs
/// - Usar o mesmo DTO para usuários, produtos, pedidos, etc.
/// - Evita duplicação de código
/// 
/// Exemplo de uso 1: Listar Usuários
/// 
/// var usuariosPaginados = new PaginacaoDto<UsuarioPaginadoDto>(
///     Itens: new[] {
///         new UsuarioPaginadoDto(...),
///         new UsuarioPaginadoDto(...),
///     },
///     PaginaAtual: 1,
///     TotalPaginas: 5,
///     TotalRegistros: 47,
///     TemProxima: true,
///     TemAnterior: false
/// );
/// 
/// Exemplo de uso 2: Listar Produtos (futuro)
/// 
/// var produtosPaginados = new PaginacaoDto<ProdutoDto>(
///     Itens: new[] {
///         new ProdutoDto(...),
///         new ProdutoDto(...),
///     },
///     PaginaAtual: 2,
///     TotalPaginas: 10,
///     TotalRegistros: 243,
///     TemProxima: true,
///     TemAnterior: true
/// );
/// 
/// Serialização JSON para usuários (página 1):
/// {
///   "itens": [
///     { "id": "...", "nomeCompleto": "João", ... },
///     { "id": "...", "nomeCompleto": "Maria", ... }
///   ],
///   "paginaAtual": 1,
///   "totalPaginas": 5,
///   "totalRegistros": 47,
///   "temProxima": true,
///   "temAnterior": false
/// }
/// 
/// Serialização JSON para usuários (página 5):
/// {
///   "itens": [
///     { "id": "...", "nomeCompleto": "Pedro", ... }
///   ],
///   "paginaAtual": 5,
///   "totalPaginas": 5,
///   "totalRegistros": 47,
///   "temProxima": false,
///   "temAnterior": true
/// }
/// 
/// </summary>
/// <typeparam name="T">
/// O tipo de dados que será paginado.
/// Exemplos: UsuarioPaginadoDto, ProdutoDto, PedidoDto, etc.
/// </typeparam>
public record PaginacaoDto<T>(
    /// <summary>
    /// Coleção de itens da página atual.
    /// 
    /// Tipo: IEnumerable<T>
    /// Por que IEnumerable? Permite qualquer coleção (List, Array, etc)
    /// 
    /// Quantidade: Até itensPorPagina (geralmente 10)
    /// 
    /// Exemplo (página 1 com 10 itens):
    /// Itens: [usuario1, usuario2, ..., usuario10]
    /// 
    /// Exemplo (página 5 com menos de 10 itens - última página):
    /// Itens: [usuario41, usuario42, usuario43, usuario44, usuario45, usuario46, usuario47]
    /// (7 itens na última página)
    /// 
    /// Função: Os dados reais para exibir ao usuário
    /// 
    /// Segurança: Cada item já passou pelo DTO (dados sensíveis já foram removidos)
    /// </summary>
    IEnumerable<T> Itens,

    /// <summary>
    /// Número da página atual.
    /// 
    /// Tipo: int
    /// Valores: 1, 2, 3, ... até TotalPaginas
    /// 
    /// Exemplo: Se PaginaAtual = 2 e TotalPaginas = 5
    /// Significa que estamos na página 2 de 5
    /// 
    /// Cálculo no banco:
    /// skip = (paginaAtual - 1) * itensPorPagina
    /// take = itensPorPagina
    /// 
    /// Exemplo: paginaAtual = 2, itensPorPagina = 10
    /// skip = (2 - 1) * 10 = 10
    /// take = 10
    /// Resultado: itens de índice 10 a 19
    /// 
    /// Uso no frontend:
    /// console.log(`Página ${response.paginaAtual} de ${response.totalPaginas}`);
    /// // Output: "Página 2 de 5"
    /// </summary>
    int PaginaAtual,

    /// <summary>
    /// Número total de páginas.
    /// 
    /// Tipo: int
    /// Cálculo: Math.Ceiling((decimal)TotalRegistros / itensPorPagina)
    /// 
    /// Exemplo 1: 47 registros, 10 por página
    /// Math.Ceiling(47 / 10) = Math.Ceiling(4.7) = 5 páginas
    /// 
    /// Exemplo 2: 50 registros, 10 por página
    /// Math.Ceiling(50 / 10) = 5 páginas
    /// 
    /// Exemplo 3: 51 registros, 10 por página
    /// Math.Ceiling(51 / 10) = 6 páginas
    /// 
    /// Uso no frontend:
    /// // Renderizar botões de página
    /// for (let p = 1; p <= response.totalPaginas; p++) {
    ///     criarBotaoPagina(p);
    /// }
    /// </summary>
    int TotalPaginas,

    /// <summary>
    /// Quantidade TOTAL de registros em TODAS as páginas.
    /// 
    /// Tipo: int
    /// 
    /// Exemplo: TotalRegistros = 47
    /// Significa que há 47 usuários no banco, distribuídos em 5 páginas
    /// 
    /// Diferença entre Itens.Count() e TotalRegistros:
    /// 
    /// Página 1:
    /// - Itens.Count() = 10 (10 itens nesta página)
    /// - TotalRegistros = 47 (total em todas as páginas)
    /// 
    /// Página 5 (última):
    /// - Itens.Count() = 7 (7 itens nesta última página)
    /// - TotalRegistros = 47 (total em todas as páginas)
    /// 
    /// Uso no frontend:
    /// console.log(`Mostrando ${response.itens.length} de ${response.totalRegistros}`);
    /// // Página 1: "Mostrando 10 de 47"
    /// // Página 5: "Mostrando 7 de 47"
    /// </summary>
    int TotalRegistros,

    /// <summary>
    /// Indica se existe próxima página.
    /// 
    /// Tipo: bool
    /// Valor: true se PaginaAtual < TotalPaginas, false caso contrário
    /// 
    /// Cálculo: temProxima = paginaAtual < totalPaginas
    /// 
    /// Exemplo 1: PaginaAtual = 2, TotalPaginas = 5
    /// temProxima = 2 < 5 = true (existe próxima)
    /// 
    /// Exemplo 2: PaginaAtual = 5, TotalPaginas = 5
    /// temProxima = 5 < 5 = false (é a última)
    /// 
    /// Uso no frontend:
    /// if (response.temProxima) {
    ///     mostrarBotaoProxima();
    /// }
    /// </summary>
    bool TemProxima,

    /// <summary>
    /// Indica se existe página anterior.
    /// 
    /// Tipo: bool
    /// Valor: true se PaginaAtual > 1, false caso contrário
    /// 
    /// Cálculo: temAnterior = paginaAtual > 1
    /// 
    /// Exemplo 1: PaginaAtual = 2, TotalPaginas = 5
    /// temAnterior = 2 > 1 = true (existe anterior)
    /// 
    /// Exemplo 2: PaginaAtual = 1, TotalPaginas = 5
    /// temAnterior = 1 > 1 = false (é a primeira)
    /// 
    /// Uso no frontend:
    /// if (response.temAnterior) {
    ///     mostrarBotaoAnterior();
    /// }
    /// </summary>
    bool TemAnterior
);