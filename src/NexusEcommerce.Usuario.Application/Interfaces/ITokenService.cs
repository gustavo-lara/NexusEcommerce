// Importações necessárias
using NexusEcommerce.Usuario.Domain.Enums;

// Namespace que agrupa interfaces da camada de aplicação
namespace NexusEcommerce.Usuario.Application.Interfaces;

/// <summary>
/// Interface que define as operações de geração e validação de tokens JWT e Refresh Tokens.
/// 
/// Esta interface é o CONTRATO que qualquer implementação de TokenService deve respeitar.
/// 
/// Por que uma interface?
/// 1. DESACOPLAMENTO: Quem usa não precisa conhecer os detalhes de implementação
/// 2. TESTABILIDADE: Fácil mockar para testes unitários
/// 3. FLEXIBILIDADE: Trocar implementação sem alterar quem chama
/// 4. CLAREZA: Define exatamente o que o serviço faz
/// 
/// Implementação: TokenService (PASSO 08)
/// 
/// Uso:
/// - IniciarProjeto() → builder.Services.AddScoped<ITokenService, TokenService>();
/// - LoginService injetar ITokenService (não TokenService)
/// - AutenticacaoService injetar ITokenService (não TokenService)
/// 
/// Exemplo de DI:
/// public class LoginService
/// {
///     private readonly ITokenService _tokenService;  // ✅ Interface, não implementação
///     
///     public LoginService(ITokenService tokenService)
///     {
///         _tokenService = tokenService;
///     }
/// }
/// 
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Gera um novo JWT (JSON Web Token) para autorizar requisições.
    /// 
    /// JWT (JSON Web Token) é um padrão aberto (RFC 7519) para representar informações
    /// com segurança entre duas partes.
    /// 
    /// ESTRUTURA DO JWT:
    /// ─────────────────────────────────────────────────────────────────────────────
    /// header.payload.signature
    /// ─────────────────────────────────────────────────────────────────────────────
    /// 
    /// header (Base64URL decodificado):
    /// {
    ///   "alg": "HS256",      // Algoritmo de criptografia (HmacSHA256)
    ///   "typ": "JWT"         // Tipo: JSON Web Token
    /// }
    /// 
    /// payload (Base64URL decodificado):
    /// {
    ///   "sub": "user-123",                    // subject (quem é)
    ///   "email": "joao@example.com",          // Email
    ///   "role": "Moderador",                  // Papel
    ///   "role_value": "1",                    // Papel em número
    ///   "iat": 1681379445,                    // Issued At (quando foi criado)
    ///   "exp": 1681383045,                    // Expiration (quando expira) - 60 min depois
    ///   "iss": "NexusEcommerce",              // Issuer (quem criou)
    ///   "aud": "NexusEcommerceUsers"          // Audience (para quem é)
    /// }
    /// 
    /// signature (gerado com chave secreta):
    /// HMACSHA256(
    ///   base64UrlEncode(header) + "." + base64UrlEncode(payload),
    ///   "sua-chave-secreta-super-segura-min-32-caracteres"
    /// )
    /// 
    /// O JWT COMPLETO FICA ASSIM:
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImVtYWlsIjoiam9hb0BleGFtcGxlLmNvbSIsInJvbGUiOiJNb2Rlcm...
    /// 
    /// COMO FUNCIONA A SEGURANÇA:
    /// ──────────────────────────
    /// 1. Servidor cria JWT assinando com chave secreta
    /// 2. Cliente recebe JWT e armazena (navegador, app mobile)
    /// 3. Cliente envia JWT em cada requisição no header Authorization
    /// 4. Servidor recebe JWT e valida:
    ///    a) Decodifica header e payload (qualquer um consegue decodificar)
    ///    b) Regenera a assinatura com a chave secreta
    ///    c) Compara assinatura recebida com gerada
    ///    d) Se forem iguais, JWT é válido
    ///    e) Se forem diferentes, alguém alterou o JWT (rejeita)
    /// 5. Se JWT é válido, servidor também valida:
    ///    - Issuer: é nosso servidor?
    ///    - Audience: é para nossa aplicação?
    ///    - Expiration: não expirou?
    /// 6. Se tudo OK, processa a requisição
    /// 
    /// IMPORTANTE: JWT não é privado!
    /// ──────────────────────────────────
    /// Qualquer um consegue decodificar o conteúdo (base64 é codificação, não criptografia)
    /// A segurança vem da ASSINATURA (só quem tem a chave secreta consegue assinar)
    /// Por isso NUNCA colocar informações confidenciais no JWT (ex: senha, cartão de crédito)
    /// 
    /// FLUXO:
    /// ──────
    /// 1. Login: email + senha → JWT + RefreshToken
    /// 2. Requisição: Authorization: Bearer <JWT> → acesso à API
    /// 3. Quando JWT expira: RefreshToken → novo JWT
    /// 4. Logout: marcar RefreshToken como revogado
    /// 
    /// TEMPO DE VIDA (TTL):
    /// ────────────────────
    /// Geralmente 60 minutos (curto para segurança)
    /// - Muito curto: usuário precisa fazer refresh frequente (ruim UX)
    /// - Muito longo: se JWT for roubado, fica exposto por mais tempo (ruim segurança)
    /// - 60 minutos: equilíbrio entre segurança e UX
    /// 
    /// Se JWT expira, cliente usa RefreshToken para gerar novo JWT (sem pedir login de novo)
    /// Se RefreshToken expira, usuário precisa fazer login de novo
    /// 
    /// </summary>
    /// <param name="identityId">
    /// ID do usuário no ASP.NET Core Identity.
    /// 
    /// Tipo: string
    /// Origem: IdentityUser.Id
    /// Função: Identificar o usuário no token
    /// 
    /// Exemplo: "550e8400-e29b-41d4-a716-446655440000"
    /// 
    /// Este ID é único no ASP.NET Core Identity
    /// Será incluído como "sub" (subject) no JWT
    /// </param>
    /// <param name="email">
    /// Email do usuário.
    /// 
    /// Tipo: string
    /// Origem: IdentityUser.Email (normalizado)
    /// Função: Identificar o usuário e exibir na UI
    /// 
    /// Exemplo: "joao@example.com"
    /// 
    /// Será incluído como "email" claim no JWT
    /// </param>
    /// <param name="role">
    /// Papel (role) do usuário no sistema.
    /// 
    /// Tipo: UserRole (enum)
    /// Valores: Cliente (0), Moderador (1), Administrador (2)
    /// Origem: Cliente.Role
    /// Função: Controle de acesso (autorização)
    /// 
    /// Exemplo: UserRole.Moderador
    /// 
    /// Será incluído no JWT como:
    /// - "role": "Moderador" (string para legibilidade)
    /// - "role_value": "1" (número para performance)
    /// 
    /// O controller usa o role do JWT para autorizar:
    /// [Authorize(Roles = "Administrador,Moderador")]
    /// public async Task<IActionResult> ListarUsuarios() { ... }
    /// </param>
    /// <returns>
    /// String contendo o JWT.
    /// 
    /// Formato: header.payload.signature (em Base64URL)
    /// Tamanho: Típicamente 300-500 caracteres
    /// 
    /// Exemplo (truncado):
    /// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImVtYWlsIjoiam9hb0BleGFtcGxlLmNvbSIsInJvbGUiOiJNb2Rlcm..."
    /// 
    /// Este token deve ser:
    /// 1. Armazenado no cliente (localStorage, sessionStorage, memory)
    /// 2. Enviado em cada requisição como: Authorization: Bearer <token>
    /// 3. Validado pelo middleware antes de processar requisição
    /// </returns>
    string GerarAccessToken(string identityId, string email, UserRole role);

    /// <summary>
    /// Gera um novo refresh token aleatório e seguro.
    /// 
    /// REFRESH TOKEN vs ACCESS TOKEN:
    /// ────────────────────────────────
    /// Access Token (JWT):
    /// - Contém dados do usuário (claims)
    /// - Criptografado e assinado
    /// - Curto (60 minutos)
    /// - Usado a cada requisição
    /// 
    /// Refresh Token (aleatório):
    /// - Simples string aleatória
    /// - Armazenado NO BANCO (importante!)
    /// - Longo (7 dias)
    /// - Usado apenas para gerar novo access token
    /// 
    /// POR QUE DOIS TOKENS?
    /// ────────────────────
    /// Se usássemos apenas um token com 7 dias:
    /// - Muito tempo exposto se roubado
    /// - Logout não funcionaria (ainda seria válido)
    /// 
    /// Com dois tokens:
    /// - Access token curto: menos tempo exposto
    /// - Refresh token longo: renovação automática sem pedir login de novo
    /// - Logout real: marca refresh como revogado
    /// 
    /// COMO FUNCIONA:
    /// ──────────────
    /// 1. Usuário faz login
    /// 2. Recebe access token (60 min) + refresh token (7 dias)
    /// 3. Usa access token para requisições (não precisa do banco)
    /// 4. Quando access token expira (60 min depois)
    /// 5. Cliente envia refresh token para renovar
    /// 6. Servidor valida refresh token NO BANCO
    /// 7. Se OK: gera novo access token + novo refresh token
    /// 8. Processo se repete até refresh token expirar (7 dias)
    /// 
    /// GERAÇÃO:
    /// ────────
    /// 1. Cria array de 32 bytes aleatórios
    /// 2. Usa RandomNumberGenerator (criptografia forte)
    /// 3. Converte para Base64
    /// 4. Retorna string
    /// 
    /// EXEMPLO DE GERAÇÃO (em C#):
    /// using (var rng = RandomNumberGenerator.Create())
    /// {
    ///     var bytes = new byte[32];  // 256 bits
    ///     rng.GetBytes(bytes);       // Preenche com aleatoriedade
    ///     return Convert.ToBase64String(bytes);
    /// }
    /// 
    /// SEGURANÇA:
    /// ──────────
    /// - 256 bits de entropia (32 bytes)
    /// - Computacionalmente impossível adivinhar
    /// - Cada refresh token é único
    /// - Armazenado no banco com hash (opcional, dependendo de segurança)
    /// 
    /// EXEMPLO DE RESULTADO:
    /// "v/bKa5f8nM2pQ9xL7wS4rT1u3vY6zX8BnOpQrStUvWxYz="
    /// (43 caracteres em Base64 = 32 bytes em binário)
    /// 
    /// </summary>
    /// <returns>
    /// String aleatória segura em Base64.
    /// 
    /// Características:
    /// - 32 bytes de aleatoriedade (256 bits)
    /// - Convertido para Base64 (43-44 caracteres)
    /// - Cada chamada gera um novo token
    /// - Nunca repete (probabilidade matemática negligenciável)
    /// 
    /// Este token será:
    /// 1. Salvo no banco (RefreshTokens table)
    /// 2. Enviado para o cliente
    /// 3. Armazenado no cliente (localStorage, sessionStorage, etc)
    /// 4. Enviado para /api/auth/refresh-token quando access token expirar
    /// </returns>
    string GerarRefreshToken();

    /// <summary>
    /// Valida se um refresh token é válido e ativo.
    /// 
    /// VALIDAÇÕES REALIZADAS:
    /// ──────────────────────
    /// 1. Token existe no banco?
    /// 2. Pertence ao usuário informado?
    /// 3. Não foi revogado (logout)?
    /// 4. Não expirou?
    /// 
    /// EXEMPLO DE QUERY SQL:
    /// SELECT * FROM RefreshTokens
    /// WHERE Token = @token
    ///   AND IdentityUserId = @identityId
    ///   AND Revogado = false
    ///   AND ExpiraEm > GETUTCDATE()
    /// 
    /// RETORNA:
    /// - Se encontrar 1 registro: true (token válido)
    /// - Se encontrar 0 registros: false (token inválido/expirado/revogado)
    /// 
    /// POR QUE ESTE MÉTODO?
    /// ────────────────────
    /// Refresh tokens são armazenados no banco porque precisamos poder:
    /// 1. Invalidar (logout): marcar como revogado
    /// 2. Rastrear (auditoria): saber quando foi criado/usado
    /// 3. Auditar (segurança): IP e User Agent
    /// 
    /// Access tokens (JWT) não são armazenados (fast, stateless)
    /// Refresh tokens SÃO armazenados (permite controle)
    /// 
    /// FLUXO DE USO:
    /// ─────────────
    /// 1. Cliente envia refresh token para /api/auth/refresh-token
    /// 2. TokenService.ValidarRefreshTokenAsync() valida no banco
    /// 3. Se retorna true:
    ///    - Revoga o refresh token antigo
    ///    - Cria novo access token
    ///    - Cria novo refresh token
    ///    - Retorna ambos
    /// 4. Se retorna false:
    ///    - Lança exceção ou retorna erro 401
    ///    - Cliente precisa fazer login de novo
    /// 
    /// </summary>
    /// <param name="token">
    /// O refresh token a validar.
    /// 
    /// Tipo: string
    /// Formato: Base64 aleatório (gerado por GerarRefreshToken())
    /// 
    /// Exemplo: "v/bKa5f8nM2pQ9xL7wS4rT1u3vY6zX8B..."
    /// 
    /// Este é o token que o cliente enviou
    /// Será buscado no banco para validar
    /// </param>
    /// <param name="identityId">
    /// ID do usuário que está tentando usar o token.
    /// 
    /// Tipo: string
    /// Origem: JWT claim "sub" (NameIdentifier)
    /// 
    /// Função: Garantir que o token pertence ao usuário
    /// 
    /// Segurança: Evita que usuario A use refresh token de usuario B
    /// 
    /// Exemplo: "550e8400-e29b-41d4-a716-446655440000"
    /// </param>
    /// <returns>
    /// true se o token é válido e ativo
    /// false se o token é inválido, revogado ou expirou
    /// 
    /// IMPORTANTE: Este método não lança exceção!
    /// Apenas retorna bool para permitir ao chamador decidir o que fazer.
    /// </returns>
    Task<bool> ValidarRefreshTokenAsync(string token, string identityId);

    /// <summary>
    /// Revoga um refresh token (marca como inválido).
    /// 
    /// Revogação significa: marca o token como não mais utilizável
    /// 
    /// QUANDO USAR:
    /// ────────────
    /// 1. LOGOUT: usuário faz logout → revoga seu refresh token
    /// 2. REFRESH: ao renovar token → revoga o antigo, cria novo
    /// 3. SEGURANÇA: suspeita de comprometimento → revoga todos os tokens
    /// 4. EXPIRAÇÃO: limpeza periódica de tokens expirados
    /// 
    /// O QUE MUDA NO BANCO:
    /// ────────────────────
    /// UPDATE RefreshTokens
    /// SET Revogado = true,
    ///     RevogadoEm = GETUTCDATE()
    /// WHERE Token = @token
    ///   AND IdentityUserId = @identityId
    /// 
    /// EFEITO:
    /// ───────
    /// Após revogação:
    /// - ValidarRefreshTokenAsync() retorna false
    /// - Token não pode mais ser usado para refresh
    /// - Mesmo se não expirou ainda
    /// - Usuário precisa fazer login de novo
    /// 
    /// FLUXO DE LOGOUT:
    /// ────────────────
    /// 1. Usuário clica em "Logout"
    /// 2. Cliente envia: DELETE /api/auth/logout + refresh token
    /// 3. Servidor chama: RevogarRefreshTokenAsync(token, identityId)
    /// 4. Banco marca token como revogado
    /// 5. Mesmo se alguém conseguir o token, não funciona mais
    /// 6. ✅ Logout real e imediato!
    /// 
    /// SEGURANÇA (Logout Real):
    /// ────────────────────────
    /// COM revogação:
    /// - Logout funciona imediatamente
    /// - Token roubado é inútil após revogação
    /// 
    /// SEM revogação (apenas TTL):
    /// - Logout não funciona de verdade
    /// - Token continua válido até expirar (7 dias)
    /// - Se alguém roubar, pode usar por semana inteira
    /// 
    /// </summary>
    /// <param name="token">
    /// O refresh token a revogar.
    /// 
    /// Tipo: string
    /// Formato: Base64 aleatório
    /// 
    /// Exemplo: "v/bKa5f8nM2pQ9xL7wS4rT1u3vY6zX8B..."
    /// </param>
    /// <param name="identityId">
    /// ID do usuário que está revogando o token.
    /// 
    /// Tipo: string
    /// Função: Garantir que o token pertence ao usuário
    /// 
    /// Segurança: Evita que usuario A revogue token de usuario B
    /// 
    /// Exemplo: "550e8400-e29b-41d4-a716-446655440000"
    /// </param>
    /// <returns>
    /// Task (void assincronamente).
    /// 
    /// Não retorna nada (fire and forget).
    /// Se houver erro, será propagado como exceção.
    /// </returns>
    Task RevogarRefreshTokenAsync(string token, string identityId);
}