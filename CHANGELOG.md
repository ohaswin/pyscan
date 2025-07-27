# Changelog

## 0.1.1

- added package subcommand, here's a quick usage:

```bash
pyscan package -n jinja2 -v 2.4.1
```

- slight logic improvments
- notes for next release:
- - if it detects toml but it doesnt find the dependencies table it panics, no idea how to err handle that for now
- - I should probably start using the `anyhow`  crate.
- - `get_latest_package_version` should become its own function and be moved to `utils.rs` in the next version

That's all for this release!

## 0.1.2

- added docker subcommand, usage:
```bash
> pyscan docker -n my-docker-image -p /path/inside/container/to/source
```

by <i>"source"</i> I mean `requirements.txt`, `pyproject.toml` or your python files.

- pyscan will not be using [deps.dev](https://deps.dev) API anymore to retrive latest stable versions. Will be using `pip` instead to get the installed package version from the user. Should've thought of that sooner. [credits to @anotherbridge for [#1](https://github.com/ohaswin/pyscan/issues/1)]
  
-  better error messages, though panics are the main way of displaying them.
  
-  This release was pretty rushed to fix that issue and get the docker feature on. I will be taking my sweet time with the next release to get:
  
- - github actions integration
- - make it easier for other tools to interact with pyscan
- - code complexity analyzer (not doing a linter cuz any respectable python dev already has one)
- - finally get to do tests, and lots of more ideas in my head. Thanks for the awesome support so far!

## 0.1.3

- Fixed a grave error where docker command left remnants and did not perform a complete cleanup.
- This release was made right after the previous release to fix this feature, however, the release page will contain both this message and the previous one so no one will miss out on the new stuff.

## 0.1.4 (the "big" update)

### Changes and New

- BATCHED API! Pyscan is actually fast enough now. [#5]
- Less panics and more user friendly errors.
- Perfomance optimizations by some &s and better logic.
- Support for constraints.txt [#4]
- Introduced PipCache, which caches your pip package names and versions before the execution of the scanner to quickly lookup incase of a fallback
- also, fallbacks! [#3] the order is: source > pip > pypi.org
- it can be disabled with only sticking to `--pip` or `--pypi` or `--source`
- exit non-zeros at vulns found and other important errors

### Notes
- I actually wanted to include multi-threaded batched requests to increase perfomance even more
- but had to rush the update because everyone was installing the pathetic previous one. It's like hiding a golden apple that you can't show anyone. (except people who noticed the alpha branch) 
- I will try not to rush updates and actually take things slow but thats hard when its recieving so much attention
- [RealPython](realpython.com) featured this project on their podcast which was just amazing, and something that has never happened to me before.
- Twitter and imageboards (the good ones) are giving pyscan so much love.
- All the issue makers have led to some very awesome improvements, I fucking love open source.

That's about it, check TODO for whats coming in the future.

## v0.1.6 (October 15, 2023)

*v0.1.5 had a bugfix to fix a critical bug accidently deployed in v0.1.4, immediately. Thus, i dont think it deserves its own thingy.*

### New Features

- implement parsing dependencies from `setup.py`,`setuptools`,`poetry`,`hatch`,`filt`, `pdm`
- multithreaded requests for `> 100` dependencies
- output options

### Fixes

This version was focused on:

- #13 [fixed]
- #14 [fixed]
- #11 - This will took some time as parsing of pyproject.toml is hard-coded to only support PEP 621, which means redesigning how pyproject.toml should be scanned entirely. [fixed]

### Notes

Pyscan has some **very interesting developments** planned in the future. Checkout the PR.

- [ ] the crate `pep-508` seems to be having trouble parsing embedded hash values in `requirements.txt` ( #16 ), which may or may not have a fix depending on the author of the lib.
- [ ] (maybe) support for parsing SBOMs and KBOMs
- [ ] (maybe) introduce displaying severity, along with a filter for known vuln IDs.


## v0.1.7 (December 24,2024)

### Notes

- Includes critical bug fixes for #19 and #20
- Fixes up the parsing logic a bit

The PR and the "big" update is still an ongoing effort, slowed down due to my recent lack of time (college, part-time work).

Consider **donating** if you *actually* use this tool, as I'm thinking about archiving it after some maintanence done.

## v0.1.8 (July 27, 2025)

### Notes

- Add feature: Ignore specific vulnerability IDs using a .pyscanignore file either at cwd or config folder of the OS (global)
- Improve CI to include much more platforms, except for 2 obscure ones due to assembly issues (s390x, ppc64le) hopefully all 0 of their users are not annoyed at me.
- Nothing much, honestly, look at the last changelog date. College has been crazy, I've been doing internships and side gigs and working meself to the bone. Still broke, but at least I know how shitty this codebase is now, and I'm grateful that i hold the awareness to realize that after 3 years lol.