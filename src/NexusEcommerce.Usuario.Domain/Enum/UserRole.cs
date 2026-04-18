namespace NexusEcommerce.Usuario.Domain.Enums;

/// <summary>
/// Define os papéis (roles) disponíveis no sistema NexusEcommerce.
/// 
/// Um "role" é uma categoria que agrupa permissões. Cada usuário tem um único role,
/// que determina quais ações ele pode realizar no sistema (autorização).
/// 
/// Exemplo: um usuário com role "Administrador" pode atribuir roles a outros usuários,
/// enquanto um "Cliente" comum não pode.
/// 
/// Benefícios de usar Enum em vez de strings:
/// - Type-safety: o compilador garante que apenas valores válidos são usados
/// - Performance: armazenado como número (0, 1, 2) no banco, não como string
/// - Intellisense: VS autocomplete sugere os valores disponíveis
/// - Refatoração segura: renomear valores em um lugar só
/// </summary>
public enum UserRole
{
    /// <summary>
    /// Valor: 0
    /// Cliente padrão da plataforma.
    /// 
    /// Permissões:
    /// - Visualizar próprio perfil
    /// - Editar próprio perfil
    /// - Comprar produtos
    /// - Ver histórico de pedidos
    /// 
    /// Este é o role padrão atribuído a todo novo usuário.
    /// Outros roles são atribuídos apenas por administradores.
    /// </summary>
    Cliente = 0,

    /// <summary>
    /// Valor: 1
    /// Gerenciador de conteúdo e suporte.
    /// 
    /// Permissões:
    /// - Todas as permissões de Cliente
    /// - Listar todos os usuários
    /// - Visualizar perfil de outros usuários
    /// - Gerenciar suporte/tickets
    /// - Moderar conteúdo gerado por usuários
    /// - Ver relatórios de atividades
    /// 
    /// Role intermediário entre Cliente e Administrador.
    /// Típico para gerentes de comunidade, suporte técnico, etc.
    /// </summary>
    Moderador = 1,

    /// <summary>
    /// Valor: 2
    /// Administrador do sistema.
    /// 
    /// Permissões:
    /// - TODAS as permissões do sistema
    /// - Atribuir/remover roles de usuários
    /// - Gerenciar configurações do sistema
    /// - Acessar logs e auditoria
    /// - Gerenciar backup/restore
    /// - Criar outros administradores
    /// 
    /// Este é o papel mais privilegiado.
    /// Deve ser atribuído com muito cuidado a poucas pessoas.
    /// Qualquer ação de um administrador é crítica para o sistema.
    /// </summary>
    Administrador = 2
}
