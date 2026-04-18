// Este namespace organiza as entidades da camada de infraestrutura
// Entidades são classes que representam tabelas no banco de dados
namespace NexusEcommerce.Usuario.Infrastructure.Entities;

/// <summary>
/// Representa um token de atualização (refresh token) armazenado no banco de dados.
/// 
/// A entidade RefreshToken é essencial para um sistema de autenticação seguro porque permite:
/// 
/// 1. LOGOUT REAL
///    - Quando o usuário faz logout, marcamos este token como revogado
///    - Mesmo que alguém tenha o token, não consegue usá-lo depois de revogado
///    - Sem banco de dados, não há forma de invalidar um token antes de expirar
/// 
/// 2. AUDITORIA DE SEGURANÇA
///    - Rastreamos quem fez login (IdentityUserId)
///    - De onde fez login (IpOrigem)
///    - Com qual dispositivo/navegador (UserAgent)
///    - Quando foi revogado (RevogadoEm)
/// 
/// 3. CONTROLE DE MÚLTIPLAS SESSÕES
///    - Um usuário pode ter vários refresh tokens ativos (várias abas, dispositivos)
///    - Podemos revogar tokens específicos (ex: logout apenas em um dispositivo)
///    - Ou revogar todos (logout em todos os dispositivos)
/// 
/// 4. TOKEN SEGURO
///    - Access tokens são curtos (60 minutos) - menos tempo exposto
///    - Refresh tokens são longos (7 dias) - armazenados apenas no servidor
///    - Se alguém roubar o access token, só funciona por 60 minutos
///    - Se alguém roubar o refresh token, podemos revogar imediatamente
/// 
/// FLUXO TÍPICO:
/// 
/// Login:
///   └─ Gera JWT access token (60 min)
///   └─ Gera refresh token aleatório (7 dias)
///   └─ Salva refresh token aqui no banco
///   └─ Envia ambos para o cliente
/// 
/// Requisições normais:
///   └─ Cliente envia access token no header Authorization
///   └─ Servidor valida o JWT (checa assinatura, issuer, etc)
///   └─ Não precisa consultar banco de dados
/// 
/// Access token expirou:
///   └─ Cliente recebe 401 Unauthorized
///   └─ Cliente envia refresh token para /api/auth/refresh-token
///   └─ Servidor busca refresh token aqui no banco
///   └─ Valida: existe? não foi revogado? não expirou?
///   └─ Se OK: gera novo access token
///   └─ Se OK: revoga este refresh token antigo
///   └─ Se OK: cria novo refresh token
///   └─ Retorna novo par de tokens
/// 
/// Logout:
///   └─ Cliente envia refresh token para /api/auth/logout
///   └─ Servidor busca refresh token aqui no banco
///   └─ Marca como Revogado = true
///   └─ Salva RevogadoEm = DateTime.UtcNow
///   └─ Mesmo se refresh token não expirou, agora é inútil
/// 
/// </summary>
public class RefreshToken
{
    /// <summary>
    /// Identificador único do refresh token.
    /// 
    /// Tipo: Guid (Global Unique Identifier)
    /// Por que Guid? Porque é único, não sequencial e seguro criptograficamente
    /// 
    /// Função: Chave primária (PK) da tabela RefreshTokens no banco
    /// Inicialização: Gerado automaticamente com Guid.NewGuid()
    /// 
    /// Exemplo: 550e8400-e29b-41d4-a716-446655440000
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// ID do usuário no ASP.NET Core Identity.
    /// 
    /// Tipo: string (porque o Identity usa string para IDs)
    /// 
    /// Função: Chave estrangeira (FK) que vincula este token ao usuário
    /// Relação: Um usuário pode ter MÚLTIPLOS refresh tokens
    ///          (ex: login em vários dispositivos simultâneos)
    /// 
    /// Exemplo: "user-123-uuid-aqui"
    /// 
    /// IMPORTANTE: Este é o identificador do aspnetusers na tabela do Identity
    /// Não é o mesmo que Cliente.Id (que é a tabela de negócio)
    /// Mas Cliente.IdentityId aponta para este ID
    /// 
    /// Fluxo:
    ///   Cliente.IdentityId → AspNetUsers.Id → RefreshToken.IdentityUserId
    /// </summary>
    public string IdentityUserId { get; set; } = string.Empty;

    /// <summary>
    /// O token de atualização em si (criptografado ou hash).
    /// 
    /// Tipo: string
    /// Formato: Base64 (aleatório e seguro)
    /// Tamanho: Geralmente 44 caracteres quando codificado em Base64
    ///
    /// Função: O valor que o cliente envia para renovar o access token
    /// 
    /// SEGURANÇA:
    /// - Nunca enviar para o cliente em texto claro em respostas de erro
    /// - Nunca registrar (log) em texto claro
    /// - Usar hashing se possível em produção
    /// - Armazenar com cuidado (é como uma senha)
    /// 
    /// Exemplo: "v/bKa5f8nM2pQ9xL7wS4rT1u3vY6zX8BnOpQrStUvWxYz="
    /// 
    /// Como é gerado?
    /// using (var rng = RandomNumberGenerator.Create())
    /// {
    ///     var bytes = new byte[32];
    ///     rng.GetBytes(bytes);
    ///     var token = Convert.ToBase64String(bytes);
    /// }
    /// 
    /// Por que 32 bytes? 
    /// - Segurança recomendada: mínimo 256 bits (32 bytes)
    /// - É computacionalmente impossível adivinhar
    /// - Não impede força bruta, mas impede ataques por tempo de processamento
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Data e hora quando o refresh token foi criado.
    /// 
    /// Tipo: DateTime em UTC (Coordinated Universal Time)
    /// Por que UTC? Evita problemas de fuso horário
    /// 
    /// Função: Auditoria e rastreamento
    /// Inicialização: DateTime.UtcNow (hora atual em UTC)
    /// 
    /// Exemplo: 2025-04-13T14:30:45.123Z
    /// 
    /// Uso:
    /// - Saber quando o usuário fez login
    /// - Detectar atividades suspeitas (muitos logins em pouco tempo)
    /// - Relatórios de segurança
    /// </summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Data e hora quando o refresh token expira.
    /// 
    /// Tipo: DateTime em UTC
    /// 
    /// Função: Invalidar automaticamente tokens antigos
    /// Inicialização: DateTime.UtcNow.AddDays(7) - 7 dias a partir de agora
    /// 
    /// Exemplo: 2025-04-20T14:30:45.123Z
    /// 
    /// Validação durante refresh-token:
    /// if (refreshToken.ExpiraEm > DateTime.UtcNow)
    /// {
    ///     // Token ainda é válido
    /// }
    /// else
    /// {
    ///     // Token expirou
    /// }
    /// 
    /// Por que 7 dias?
    /// - Curto o suficiente para segurança (compromete menos tokens)
    /// - Longo o suficiente para UX (usuário não precisa fazer login a cada hora)
    /// - Padrão da indústria (Google, Microsoft usam ~7 dias)
    /// </summary>
    public DateTime ExpiraEm { get; set; }

    /// <summary>
    /// Indica se o refresh token foi revogado (invalidado).
    /// 
    /// Tipo: bool
    /// Valor padrão: false (não revogado)
    /// 
    /// Função: Marcar tokens como inválidos após logout
    /// 
    /// Como funciona:
    /// 1. Usuário faz logout
    /// 2. Servidor busca refresh token
    /// 3. Marca: Revogado = true
    /// 4. Salva no banco
    /// 5. Token agora é inútil, mesmo se ainda não expirou
    /// 
    /// Validação durante refresh-token:
    /// if (refreshToken.Revogado)
    /// {
    ///     throw new Exception("Token foi revogado");
    /// }
    /// 
    /// IMPORTANTE: Isso permite LOGOUT REAL
    /// Sem isso, o token continuaria válido até expirar (7 dias)
    /// </summary>
    public bool Revogado { get; set; } = false;

    /// <summary>
    /// Data e hora quando o refresh token foi revogado.
    /// 
    /// Tipo: DateTime? (nullable - pode ser null se não foi revogado)
    /// Por que nullable? Se Revogado = false, esta propriedade deve ser null
    /// 
    /// Função: Auditoria - saber quando foi o logout
    /// Inicialização: null (preenchido somente quando revogar)
    /// 
    /// Exemplo:
    /// if (refreshToken.Revogado)
    /// {
    ///     Console.WriteLine($"Token revogado em: {refreshToken.RevogadoEm}");
    /// }
    /// 
    /// Uso:
    /// - Detectar padrões de logout suspeitos
    /// - Gerar relatórios de atividade
    /// - Investigar segurança
    /// </summary>
    public DateTime? RevogadoEm { get; set; } = null;

    /// <summary>
    /// Endereço IP de onde a requisição de login foi feita.
    /// 
    /// Tipo: string? (nullable)
    /// Por que nullable? Alguns cenários (ex: localhost testing) podem não ter IP
    /// 
    /// Formato: IPv4 ou IPv6
    /// Exemplo IPv4: "192.168.1.100"
    /// Exemplo IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    /// 
    /// Função: Segurança e auditoria
    /// Como capturar:
    /// var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
    /// 
    /// Uso:
    /// - Detectar logins de locais incomuns
    /// - Geoubicação: saber de qual país foi o login
    /// - Alertas: "Seu conta foi acessada do Japão em 5 minutos"
    /// - Investigar fraudes
    /// 
    /// GDPR/Privacidade:
    /// - Cuidado ao armazenar IPs
    /// - Considerado dado pessoal em alguns países
    /// - Pode precisar de consentimento
    /// - Considerar anonimizar após X dias
    /// </summary>
    public string? IpOrigem { get; set; } = null;

    /// <summary>
    /// Informações do navegador/cliente que fez o login.
    /// 
    /// Tipo: string? (nullable)
    /// Por que nullable? Nem todas as requisições têm User-Agent
    /// 
    /// Formato: String do header HTTP User-Agent
    /// Exemplo: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
    /// 
    /// Função: Identificar qual dispositivo/navegador fez login
    /// Como capturar:
    /// var userAgent = Request.Headers.UserAgent.ToString();
    /// 
    /// Informações que podemos extrair:
    /// - Sistema operacional (Windows, Mac, Linux, Android, iOS)
    /// - Navegador (Chrome, Firefox, Safari, Edge)
    /// - Versão do navegador
    /// - Dispositivo (Desktop, Mobile, Tablet)
    /// 
    /// Parâmetro "user-agents-parse" para analisar
    /// Ou usar biblioteca NuGet "UserAgentParser"
    /// 
    /// Uso:
    /// - Detectar login de novo dispositivo
    /// - "Seu conta foi acessada de iPhone em Chrome"
    /// - Criar alertas de segurança
    /// - Gerar relatórios de dispositivos usados
    /// - Permitir logout seletivo (logout apenas deste dispositivo)
    /// 
    /// GDPR/Privacidade:
    /// - User-Agent pode conter dados pessoais
    /// - Considerar armazena-lo com cuidado
    /// - Pode precisar de consentimento
    /// </summary>
    public string? UserAgent { get; set; } = null;

    /// <summary>
    /// Resumo visual da estrutura RefreshToken:
    /// 
    /// +-----------------------------------------------+
    /// | RefreshToken                                  |
    /// +-----------------------------------------------+
    /// | Id (PK)                    : Guid             |
    /// | IdentityUserId (FK)        : string           |
    /// | Token                      : string           |
    /// | CriadoEm                   : DateTime (UTC)   |
    /// | ExpiraEm                   : DateTime (UTC)   |
    /// | Revogado                   : bool             |
    /// | RevogadoEm                 : DateTime? (UTC)  |
    /// | IpOrigem                   : string?          |
    /// | UserAgent                  : string?          |
    /// +-----------------------------------------------+
    /// 
    /// Índices (para performance):
    /// - (IdentityUserId, Revogado) - buscar tokens ativos de um usuário
    /// - (ExpiraEm) - limpeza de tokens expirados
    /// 
    /// Relações:
    /// - RefreshToken.IdentityUserId → AspNetUsers.Id (1:N)
    ///   Um usuário pode ter múltiplos refresh tokens
    /// </summary>
}