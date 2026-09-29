import asyncio


async def main():
    proc = await asyncio.create_subprocess_exec(
        "python", "--version",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    print("STDOUT:", stdout.decode())
    print("STDERR:", stderr.decode())
    print("Return code:", proc.returncode)


asyncio.run(main())