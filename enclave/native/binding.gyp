{
  "targets": [
    {
      "target_name": "nsm",
      "sources": ["nsm.c"],
      "libraries": ["-ltinycbor"],
      "cflags": ["-std=c99", "-Wall", "-Wextra", "-Wno-error=incompatible-pointer-types"]
    }
  ]
}
