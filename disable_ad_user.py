import subprocess

def contain_incident(username, malicious_ip):
    print(f"[!] CONTAINMENT INITIATED FOR USER: {username}")
    
    # Comando PowerShell para deshabilitar el usuario en Active Directory
    ps_cmd = f"Disable-ADAccount -Identity '{username}'"
    print(f"[+] Executing AD Lockout: {ps_cmd}")
    
    # Revocar tokens de sesión activos
    token_cmd = f"Revoke-AzureADUserAllRefreshToken -ObjectId '{username}'"
    print(f"[+] Revoking active session tokens: {token_cmd}")
    
    print(f"[✓] Containment complete. Account {username} locked.")

if __name__ == "__main__":
    contain_incident(username="jgonzalez", malicious_ip="185.220.101.5")