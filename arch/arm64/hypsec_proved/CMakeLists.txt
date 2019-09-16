cmake_minimum_required(VERSION 3.14)
project(hypsec_proved C)

set(CMAKE_C_STANDARD 99)

add_library(hypsec_proved
        constants.h
        hypsec.h
        AbstractMachine.c
        BootAux.c
        BootCore.c
        BootOps.c
        MemManager.c
        MemRegion.c
        MemoryOps.c
        NPTOps.c
        NPTWalk.c
        PTAlloc.c
        PTWalk.c
        PageIndex.c
        PageManager.c
        VCPUOps.c
        VCPUOpsAux.c
        VMPower.c)