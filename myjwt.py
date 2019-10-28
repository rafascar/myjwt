import json
from datetime import datetime

import click
import pyperclip
import jwt


class JSONParamType(click.ParamType):
    """Converts JSON string to Python dict."""

    name = "JSON"

    def convert(self, value, param, ctx):
        try:
            return json.loads(value)
        except Exception:
            self.fail(f"{value!r} is not a valid JSON string.", param, ctx)


JSON = JSONParamType()


def print_payload(payload):
    """Prints an enriched, nicely formatted payload."""
    click.secho()  # Extra space.

    def append_datetime(line):
        date_str = line.split(" ")[-1].rstrip(",")
        date = datetime.fromtimestamp(int(date_str))
        timezone = date.astimezone().tzname()
        return f"{line}\t# {date} (GMT{timezone})"

    payload_str = json.dumps(payload, indent=2)
    for line in payload_str.splitlines():
        claim = line.lstrip().split(":")[0]
        if claim in ['"iat"', '"exp"']:
            line = append_datetime(line)

        click.secho(line)

    click.secho()  # Extra space.


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("--key", type=click.File("r"), help="Path to the secret key.")
@click.pass_context
def cli(ctx, key):
    """Encode and decode JSON Web Tokens.
    
    The crypto algorithm used is RS256 (RSA Signature with SHA-256);
    it uses a public/private key pair to validate/generate the signature.
    """
    ctx.ensure_object(dict)
    ctx.obj["key"] = key.read() if key else None


@cli.command()
@click.option("--iss", required=True, help='"iss" (Issuer) Claim.')
@click.option("--sub", default="sys", show_default=True, help='"sub" (Subject) Claim.')
@click.option("--aud", help='"aud" (Audience) Claim.')
@click.option(
    "--ttl", default=86_400, show_default=True, help="Seconds until key expiration."
)
@click.option("--extra", type=JSON, help="Extra payload claims.")
@click.option("--copy", is_flag=True, help="Copy JWT to clipboard.")
@click.pass_obj
def encode(obj, iss, sub, aud, ttl, extra, copy):
    """Encode a JWT."""
    private_key = obj["key"]
    if not private_key:
        raise click.UsageError('Option "--key" is required for encoding.')

    # Build payload with required claims.
    iat = datetime.utcnow().timestamp()
    payload = {"iss": iss, "sub": sub, "iat": int(iat), "exp": int(iat + ttl)}

    # Add "aud" claim if supplied.
    if aud:
        payload["aud"] = aud

    # Update payload with extra claims if supplied.
    if extra:
        payload.update(extra)

    # Generate token with payload and signature.
    token = jwt.encode(payload, key=private_key, algorithm="RS256").decode("utf-8")

    # Copy token to clipboard if asked to.
    if copy:
        pyperclip.copy(token)

    # Print result to screen.
    print_payload(payload)
    click.secho(token)


@cli.command()
@click.argument("token")
@click.pass_obj
def decode(obj, token):
    """Decode a JWT.
    
    TOKEN is the JWT to be decoded.
    """
    public_key = obj["key"]
    if public_key:
        pass
    else:
        payload = jwt.decode(token, verify=False)

    # Print token payload.
    print_payload(payload)


if __name__ == "__main__":
    cli()
