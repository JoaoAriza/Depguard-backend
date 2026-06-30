package com.joao.depguard.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/** Comando raiz da CLI do DepGuard. */
@Command(
        name = "depguard",
        mixinStandardHelpOptions = true,
        version = "DepGuard 0.0.1-SNAPSHOT",
        description = "Escaneia repositórios: dependências vulneráveis + segredos + SBOM.",
        subcommands = { ScanCommand.class }
)
public class DepGuardCli {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new DepGuardCli()).execute(args);
        System.exit(exitCode);
    }
}
