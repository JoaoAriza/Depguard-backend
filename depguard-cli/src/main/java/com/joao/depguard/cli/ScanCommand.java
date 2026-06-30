package com.joao.depguard.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Escaneia um repositório local.
 *
 * <p>Passo 0: apenas esqueleto. A ligação com o {@code Scanner} do core
 * (parser npm, OSV, segredos, emissores) entra a partir do Passo 5.
 */
@Command(name = "scan", description = "Escaneia um repositório local.")
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Caminho do repositório a escanear.")
    Path repoRoot;

    @Option(names = "--deps", description = "Habilita a engine de dependências.")
    boolean deps;

    @Option(names = "--secrets", description = "Habilita a engine de segredos.")
    boolean secrets;

    @Override
    public Integer call() {
        System.out.println("DepGuard scan — esqueleto (Passo 0).");
        System.out.println("  repoRoot = " + repoRoot);
        System.out.println("  deps     = " + deps);
        System.out.println("  secrets  = " + secrets);
        System.out.println("Engines ainda não implementados (ver docs/architecture.md §8).");
        return 0;
    }
}
