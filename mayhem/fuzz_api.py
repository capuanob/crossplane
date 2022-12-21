#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports(include=['crossplane']):
    import crossplane


@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 2)
    try:
        if choice == 0:
            single = fdp.ConsumeBool()
            comments = fdp.ConsumeBool()
            strict = fdp.ConsumeBool()
            combine = fdp.ConsumeBool()
            check_ctx = fdp.ConsumeBool()
            check_args = fdp.ConsumeBool()
            with fdp.ConsumeTemporaryFile('.nginx', all_data=True, as_bytes=False) as fname:
                crossplane.parse(fname, single=single, comments=comments, strict=strict,
                                 combine=combine, check_ctx=check_ctx, check_args=check_args)
        elif choice == 1:
            with fdp.ConsumeTemporaryFile(suffix='.nginx', all_data=True, as_bytes=False) as fname:
                crossplane.lex(fname)
        else:
            payload = fuzz_helpers.build_fuzz_dict(fdp, [str, list, dict, str, str])
            crossplane.build(payload, header=fdp.ConsumeBool())
    except TypeError as e:
        if 'integers' in str(e):
            return -1
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
