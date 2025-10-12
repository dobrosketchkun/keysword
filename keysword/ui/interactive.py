"""Interactive TUI mode for Keysword using rich."""

import sys
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich import box
import questionary
from questionary import Style

# Custom style
custom_style = Style([
    ('qmark', 'fg:#5f87ff bold'),
    ('question', 'fg:#ffffff bold'),
    ('answer', 'fg:#00ff87 bold'),
    ('pointer', 'fg:#5f87ff bold'),
    ('highlighted', 'fg:#5f87ff bold'),
    ('selected', 'fg:#00ff87'),
    ('separator', 'fg:#444444'),
    ('instruction', 'fg:#888888'),
])

console = Console()

LOGO = """
  ___   _  _______  __   __  _______  _     _  _______  ______    ______  
 |   | | ||       ||  | |  ||       || | _ | ||       ||    _ |  |      | 
 |   |_| ||    ___||  |_|  ||  _____|| || || ||   _   ||   | ||  |  _    |
 |      _||   |___ |       || |_____ |       ||  | |  ||   |_||_ | | |   |
 |     |_ |    ___||_     _||_____  ||       ||  |_|  ||    __  || |_|   |
 |    _  ||   |___   |   |   _____| ||   _   ||       ||   |  | ||       |
 |___| |_||_______|  |___|  |_______||__| |__||_______||___|  |_||______| 
"""


def show_logo():
    """Display the Keysword logo."""
    console.print(Panel(
        Align.center(Text(LOGO, style="cyan bold")),
        border_style="bright_blue",
        box=box.DOUBLE
    ))


def show_welcome():
    """Display welcome message."""
    show_logo()
    console.print()
    console.print(Panel(
        "[bold cyan]Welcome to Keysword Interactive Mode![/bold cyan]\n\n"
        "This wizard will guide you through generating cryptographic keys deterministically.\n"
        "Your keys will be derived from a password and branch configuration.\n\n"
        "[yellow]⚠ Remember: Never share your password or private keys![/yellow]",
        title="[bold]Welcome[/bold]",
        border_style="green",
        box=box.ROUNDED
    ))
    console.print()


def select_key_type() -> str:
    """Interactive key type selection."""
    key_types = [
        questionary.Choice("🔐 RSA - Traditional public key cryptography", value="RSA"),
        questionary.Choice("🌐 P-256 (NIST) - Elliptic curve cryptography", value="P-256"),
        questionary.Choice("🔑 Curve25519 - Modern encryption (X25519)", value="curve25519"),
        questionary.Choice("✍️  Ed25519 - Digital signatures", value="ed25519"),
        questionary.Choice("₿ Bitcoin - BTC private keys & addresses", value="bitcoin"),
        questionary.Choice("⛓️  Ethereum - ETH addresses", value="ethereum"),
        questionary.Choice("🔗 secp256k1 - Bitcoin/Ethereum curve", value="secp256k1"),
    ]
    
    result = questionary.select(
        "Select key type:",
        choices=key_types,
        style=custom_style
    ).ask()
    
    if result is None:
        console.print("[yellow]Operation cancelled.[/yellow]")
        sys.exit(0)
    
    return result


def get_rsa_size() -> int:
    """Get RSA key size."""
    choices = [
        questionary.Choice("1024 bits (fast, less secure)", value=1024),
        questionary.Choice("2048 bits (recommended)", value=2048),
        questionary.Choice("3072 bits (high security)", value=3072),
        questionary.Choice("4096 bits (maximum security, slow)", value=4096),
    ]
    
    result = questionary.select(
        "Select RSA key size:",
        choices=choices,
        style=custom_style
    ).ask()
    
    return result if result else 2048


def get_branches() -> List[int]:
    """Interactive branch configuration."""
    console.print()
    console.print(Panel(
        "[bold]Branch Configuration[/bold]\n\n"
        "Branches add an additional layer of security to your key derivation.\n"
        "Use large, random numbers for better security.\n\n"
        "[cyan]Examples:[/cyan]\n"
        "  • Simple: [410, 111, 222]\n"
        "  • Secure: [9876, 54321, 12345]\n"
        "  • Very secure: [999999, 123456, 777777]",
        border_style="blue"
    ))
    console.print()
    
    method = questionary.select(
        "How would you like to configure branches?",
        choices=[
            questionary.Choice("🎲 Generate random branches (recommended)", value="random"),
            questionary.Choice("✏️  Enter branches manually", value="manual"),
            questionary.Choice("⚡ Use default [410]", value="default"),
        ],
        style=custom_style
    ).ask()
    
    if method == "random":
        import random
        count = IntPrompt.ask("[cyan]How many branches?[/cyan]", default=3, console=console)
        branches = [random.randint(10000, 999999) for _ in range(count)]
        console.print(f"[green]✓[/green] Generated branches: {branches}")
        return branches
    elif method == "manual":
        while True:
            try:
                branches_str = Prompt.ask(
                    "[cyan]Enter branches (comma-separated numbers)[/cyan]",
                    default="410,111,222",
                    console=console
                )
                branches = [int(x.strip()) for x in branches_str.split(',')]
                if all(b > 0 for b in branches):
                    console.print(f"[green]✓[/green] Using branches: {branches}")
                    return branches
                else:
                    console.print("[red]✗ All branches must be positive numbers[/red]")
            except ValueError:
                console.print("[red]✗ Invalid format. Use comma-separated numbers (e.g., 410,111,222)[/red]")
    else:
        return [410]


def get_key_config() -> tuple:
    """Get key derivation depth."""
    console.print()
    console.print(Panel(
        "[bold]Key Derivation Depth[/bold]\n\n"
        "Keys are derived in a chain from your password.\n"
        "Each iteration adds more computational work.\n\n"
        "[cyan]Key Number:[/cyan] How many iterations to perform\n"
        "  • 1 = Direct derivation (fastest)\n"
        "  • 42 = 42 iterations of derivation (slower to brute-force)\n"
        "  • Higher = More secure, but slower to generate\n\n"
        "[yellow]Most users:[/yellow] Use 1 (simple and secure)\n"
        "[green]Extra paranoid:[/green] Use 10-100 (more iterations)",
        border_style="blue"
    ))
    console.print()
    
    key_number = IntPrompt.ask(
        "[cyan]How many derivation iterations?[/cyan]",
        default=1,
        console=console
    )
    
    # Automatically set key_amount = key_number (no reason to generate more)
    key_amount = key_number
    
    return key_amount, key_number


def get_generation_count() -> int:
    """Get how many final keys to generate."""
    console.print()
    return IntPrompt.ask(
        "[cyan]How many final keys do you want to generate?[/cyan]",
        default=1,
        console=console
    )


def get_password() -> bytes:
    """Interactive password input with confirmation."""
    console.print()
    console.print(Panel(
        "[bold]Password Input[/bold]\n\n"
        "[yellow]⚠ Your password is the seed for key generation![/yellow]\n\n"
        "• Use a strong, unique password\n"
        "• Same password = same keys (deterministic)\n"
        "• Never share or lose your password\n\n"
        "[dim]Minimum recommended: 16 characters with mixed case, numbers, symbols[/dim]",
        border_style="yellow"
    ))
    console.print()
    
    while True:
        password = questionary.password(
            "Enter your password:",
            style=custom_style
        ).ask()
        
        if password is None:
            console.print("[yellow]Operation cancelled.[/yellow]")
            sys.exit(0)
        
        if len(password) < 12:
            console.print("[red]✗ Password too short (minimum 12 characters recommended)[/red]")
            if not Confirm.ask("[yellow]Use this password anyway?[/yellow]", default=False, console=console):
                continue
        
        password_confirm = questionary.password(
            "Confirm your password:",
            style=custom_style
        ).ask()
        
        if password == password_confirm:
            console.print("[green]✓ Passwords match![/green]")
            return password.encode()
        else:
            console.print("[red]✗ Passwords don't match. Try again.[/red]")


def get_kdf_config() -> dict:
    """Get KDF configuration."""
    console.print()
    console.print(Panel(
        "[bold]Key Derivation Function (KDF) Configuration[/bold]\n\n"
        "Argon2 is used to derive keys from your password.\n"
        "Higher settings = more secure but slower.\n\n"
        "[cyan]Presets:[/cyan]\n"
        "  • [green]Fast:[/green] Quick generation, suitable for testing\n"
        "  • [yellow]Balanced:[/yellow] Good balance of security and speed\n"
        "  • [red]Paranoid:[/red] Maximum security, very slow",
        border_style="blue"
    ))
    console.print()
    
    preset = questionary.select(
        "Select Argon2 preset:",
        choices=[
            questionary.Choice("⚡ Fast", value="fast"),
            questionary.Choice("⚖️  Balanced (recommended)", value="balanced"),
            questionary.Choice("🔒 Paranoid", value="paranoid"),
            questionary.Choice("⚙️  Custom", value="custom"),
        ],
        style=custom_style
    ).ask()
    
    if preset == "custom":
        time_cost = IntPrompt.ask("[cyan]Time cost (iterations)[/cyan]", default=3, console=console)
        memory_cost = IntPrompt.ask("[cyan]Memory cost (KB)[/cyan]", default=102400, console=console)
        parallelism = IntPrompt.ask("[cyan]Parallelism (threads)[/cyan]", default=8, console=console)
        return {
            'time_cost': time_cost,
            'memory_cost': memory_cost,
            'parallelism': parallelism
        }
    else:
        return {'preset': preset}


def get_output_config() -> dict:
    """Get output configuration."""
    console.print()
    console.print(Panel(
        "[bold]Output Configuration[/bold]\n\n"
        "Configure how your keys will be saved.",
        border_style="blue"
    ))
    console.print()
    
    file_type = questionary.select(
        "Output format:",
        choices=[
            questionary.Choice("📄 JSON - All keys in one file", value="json"),
            questionary.Choice("📁 Separated - Private and public in separate files", value="separated"),
        ],
        style=custom_style
    ).ask()
    
    encrypt = Confirm.ask(
        "[cyan]Encrypt output files?[/cyan]",
        default=True,
        console=console
    )
    
    encryption_password = None
    if encrypt:
        while True:
            encryption_password = questionary.password(
                "Enter encryption password:",
                style=custom_style
            ).ask()
            
            if encryption_password is None:
                console.print("[yellow]Skipping encryption.[/yellow]")
                encrypt = False
                break
            
            confirm_pass = questionary.password(
                "Confirm encryption password:",
                style=custom_style
            ).ask()
            
            if encryption_password == confirm_pass:
                console.print("[green]✓ Encryption password set![/green]")
                break
            else:
                console.print("[red]✗ Passwords don't match. Try again.[/red]")
    
    return {
        'file_type': file_type,
        'encrypt': encrypt,
        'encryption_password': encryption_password,
        'force': True,  # Always force in interactive mode
        'auto_rename': False
    }


def show_summary(config: dict):
    """Display configuration summary."""
    console.print()
    console.print(Panel("[bold cyan]Configuration Summary[/bold cyan]", border_style="cyan"))
    
    table = Table(show_header=False, box=box.SIMPLE, border_style="dim")
    table.add_column("Setting", style="cyan bold")
    table.add_column("Value", style="green")
    
    table.add_row("Key Type", config['key_type'])
    if config['key_type'] == 'RSA':
        table.add_row("RSA Size", f"{config['rsa_size']} bits")
    table.add_row("Branches", str(config['branches']))
    table.add_row("Derivation Iterations", str(config['key_number']))
    table.add_row("Generation Count", str(config['generation_count']))
    table.add_row("KDF Preset", config.get('kdf_preset', 'Custom'))
    table.add_row("Output Format", config['file_type'])
    table.add_row("Encryption", "✓ Yes" if config['encrypt'] else "✗ No")
    
    console.print(table)
    console.print()


def interactive_mode(prefilled=None):
    """Main interactive mode entry point.
    
    Args:
        prefilled: Dict of pre-filled configuration values from CLI args
    """
    if prefilled is None:
        prefilled = {}
    
    try:
        # Welcome screen
        show_welcome()
        
        # Show prefilled values if any
        if prefilled:
            console.print(Panel(
                "[bold cyan]Pre-filled from command-line:[/bold cyan]\n\n" +
                "\n".join([f"  • {k}: {v}" for k, v in prefilled.items()]),
                border_style="yellow"
            ))
            console.print()
        
        if not Confirm.ask("[bold cyan]Ready to start?[/bold cyan]", default=True, console=console):
            console.print("[yellow]Goodbye![/yellow]")
            return
        
        console.clear()
        
        # Collect configuration
        config = prefilled.copy()
        
        # Step 1: Key Type
        if 'key_type' not in config:
            show_logo()
            console.print("\n[bold cyan]Step 1/7:[/bold cyan] Key Type Selection\n")
            config['key_type'] = select_key_type()
        else:
            console.print(f"[dim]Using pre-filled key type: {config['key_type']}[/dim]")
        
        # RSA size if needed
        if config['key_type'] == 'RSA' and 'rsa_size' not in config:
            config['rsa_size'] = get_rsa_size()
        elif 'rsa_size' not in config:
            config['rsa_size'] = 2048
        
        console.clear()
        
        # Step 2: Branches
        if 'branches' not in config:
            show_logo()
            console.print("\n[bold cyan]Step 2/7:[/bold cyan] Branch Configuration\n")
            config['branches'] = get_branches()
        else:
            console.print(f"[dim]Using pre-filled branches: {config['branches']}[/dim]")
        
        console.clear()
        
        # Step 3: Derivation depth
        if 'key_number' not in config:
            show_logo()
            console.print("\n[bold cyan]Step 3/7:[/bold cyan] Derivation Depth\n")
            config['key_amount'], config['key_number'] = get_key_config()
        else:
            console.print(f"[dim]Using pre-filled derivation iterations: {config['key_number']}[/dim]")
            if 'key_amount' not in config:
                config['key_amount'] = config['key_number']
        
        console.clear()
        
        # Step 4: Generation count
        if 'generation_count' not in config:
            show_logo()
            console.print("\n[bold cyan]Step 4/7:[/bold cyan] Generation Count\n")
            config['generation_count'] = get_generation_count()
        else:
            console.print(f"[dim]Using pre-filled generation count: {config['generation_count']}[/dim]")
        
        console.clear()
        
        # Step 5: Password
        show_logo()
        console.print("\n[bold cyan]Step 5/7:[/bold cyan] Password Setup\n")
        if 'password_file' in config:
            from keysword.io.readers import read_password_from_file
            console.print(f"[yellow]Reading password from file: {config['password_file']}[/yellow]")
            config['password'] = read_password_from_file(config['password_file'])
        elif 'use_mnemonic' in config:
            from keysword.io.readers import read_mnemonic
            console.print("[yellow]Using BIP39 mnemonic phrase[/yellow]")
            config['password'] = read_mnemonic(language=config.get('mnemonic_language', 'english'))
        else:
            config['password'] = get_password()
        
        console.clear()
        
        # Step 6: KDF
        if 'preset' not in config:
            show_logo()
            console.print("\n[bold cyan]Step 6/7:[/bold cyan] KDF Configuration\n")
            kdf_config = get_kdf_config()
            config.update(kdf_config)
            config['kdf_preset'] = kdf_config.get('preset', 'custom')
        else:
            console.print(f"[dim]Using pre-filled KDF preset: {config['preset']}[/dim]")
            config['kdf_preset'] = config['preset']
        
        console.clear()
        
        # Step 7: Output
        show_logo()
        console.print("\n[bold cyan]Step 7/7:[/bold cyan] Output Configuration\n")
        if 'file_type' in config and 'encrypt' in config:
            console.print(f"[dim]Using pre-filled output: {config['file_type']}, encryption: {config['encrypt']}[/dim]")
            if 'force' not in config:
                config['force'] = True
            if 'auto_rename' not in config:
                config['auto_rename'] = False
            if config['encrypt'] and 'encryption_password' not in config:
                # Need to ask for encryption password
                console.print()
                while True:
                    encryption_password = questionary.password(
                        "Enter encryption password:",
                        style=custom_style
                    ).ask()
                    
                    if encryption_password is None:
                        console.print("[yellow]Skipping encryption.[/yellow]")
                        config['encrypt'] = False
                        break
                    
                    confirm_pass = questionary.password(
                        "Confirm encryption password:",
                        style=custom_style
                    ).ask()
                    
                    if encryption_password == confirm_pass:
                        console.print("[green]✓ Encryption password set![/green]")
                        config['encryption_password'] = encryption_password
                        break
                    else:
                        console.print("[red]✗ Passwords don't match. Try again.[/red]")
        else:
            output_config = get_output_config()
            config.update(output_config)
        
        console.clear()
        
        # Summary and confirmation
        show_logo()
        show_summary(config)
        
        if not Confirm.ask("[bold green]Generate keys with these settings?[/bold green]", default=True, console=console):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
        
        console.clear()
        show_logo()
        
        # Generate keys
        console.print("\n[bold cyan]Generating keys...[/bold cyan]\n")
        
        # Import and call the generation logic
        from keysword.core.kdf import derive_key
        from keysword.core.generators import make_me_keys
        from keysword.io.writers import jsoned, separated
        
        all_keys = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Generating...", total=config['generation_count'])
            
            for num_key in range(config['generation_count']):
                password_hash = derive_key(
                    config['password'] + str(num_key).encode(),
                    iterations=2,
                    **{k: v for k, v in config.items() if k in ['preset', 'time_cost', 'memory_cost', 'parallelism']}
                )
                
                keys = make_me_keys(
                    password=password_hash,
                    key_type=config['key_type'],
                    key_amount=config['key_amount'],
                    size_rsa=config['rsa_size'],
                    branches=config['branches'],
                    show_progress=False  # Disable internal progress bars in interactive mode
                )
                
                key = dict(keys)[config['key_number']]
                all_keys.append(key)
                progress.update(task, advance=1)
        
        console.print("[green]✓ Keys generated successfully![/green]\n")
        
        # Format and save keys
        console.print("[cyan]Saving keys...[/cyan]")
        
        from keysword.core.formats import KeyFormatter
        decoded_keys = []
        
        for the_key in all_keys:
            formats = KeyFormatter.export_key(the_key, config['key_type'])
            # Convert to simple dict format
            if config['key_type'] in ['ethereum']:
                decoded_keys.append({'secret': the_key['key'], 'address': the_key['address']})
            elif config['key_type'] == 'bitcoin':
                from bitcoin import encode_privkey, privkey_to_address
                sec = encode_privkey(the_key[:64], 'wif_compressed')
                addr = privkey_to_address(the_key[:64])
                decoded_keys.append({'secret': sec, 'address': addr})
            elif 'pem' in formats:
                decoded_keys.append({'secret': formats['pem'], 'public': formats.get('pem_public', '')})
            elif 'hex_secret' in formats:
                decoded_keys.append({'secret': formats['hex_secret'], 'public': formats['hex_public']})
            else:
                decoded_keys.append(formats)
        
        # Save to file
        if config['file_type'] == 'json':
            jsoned(
                decoded_keys,
                config['key_type'],
                encrypt=config['encrypt'],
                encryption_password=config['encryption_password'],
                force=config['force'],
                auto_rename=config['auto_rename'],
                deterministic_names=False,
                branches=config['branches'],
                key_number=config['key_number'],
                key_amount=config['key_amount']
            )
        else:
            separated(
                decoded_keys,
                config['key_type'],
                encrypt=config['encrypt'],
                encryption_password=config['encryption_password'],
                force=config['force'],
                auto_rename=config['auto_rename'],
                deterministic_names=False,
                branches=config['branches'],
                key_number=config['key_number'],
                key_amount=config['key_amount']
            )
        
        console.print("[green]✓ Keys saved successfully![/green]\n")
        
        # Final message
        console.print(Panel(
            "[bold green]✓ Complete![/bold green]\n\n"
            f"Generated {config['generation_count']} key(s) successfully!\n\n"
            + ("[yellow]⚠ Your keys are encrypted. Keep your encryption password safe![/yellow]\n\n" if config['encrypt'] else "[red]⚠ Your keys are NOT encrypted! Store them securely![/red]\n\n")
            + "[dim]Check the current directory for your key files.[/dim]",
            title="[bold]Success[/bold]",
            border_style="green",
            box=box.DOUBLE
        ))
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Operation cancelled by user.[/yellow]")
    except Exception as e:
        console.print(f"\n\n[red]Error: {e}[/red]")
        import traceback
        console.print("[dim]" + traceback.format_exc() + "[/dim]")


if __name__ == '__main__':
    interactive_mode()

