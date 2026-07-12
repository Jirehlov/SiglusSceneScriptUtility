# SiglusSceneScriptUtility

This utility aims to reproduce **SiglusEngine** SceneScript compilation as exactly as possible, along with other related (and unrelated) features.

## Documentation

See the **[English Manual](https://github.com/Jirehlov/SiglusSceneScriptUtility/blob/main/manual.md)** or **[中文手册](https://github.com/Jirehlov/SiglusSceneScriptUtility/blob/main/manual_cn.md)** for installation instructions, complete reference of all modes, options, examples, and tips. See the **[Changelog](https://github.com/Jirehlov/SiglusSceneScriptUtility/blob/main/changelog.md)** for recent updates.

## Quick Examples

Extract `Scene.pck` to a working directory:

```bash
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work
```

After editing `.ss` files, compile back into a new `.pck`:

```bash
siglus-ssu -c /path/to/translation_work /path/to/Scene_translated.pck
```

See the manuals for more modes, options, and troubleshooting tips.

## License

This project is dual-licensed under the **Unlicense** or **BSD Zero Clause
License (0BSD)**. You may choose either license.
