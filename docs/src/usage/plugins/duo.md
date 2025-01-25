# Duo

## duo.get_grant_token(auth_url)

> Handles Duo Security MFA stages and returns the grant_token used to finish logging into Synack
>
> | Arguments | Description
> | --- | ---
> | `auth_url` | Duo Security Authentication URL generaated by sending credentials to Synack
>
>> Examples
>> ```python3
>> >>> h.duo.get_grant_token('https:///...duosecurity.com/...')
>> 'Y8....6g'
>> ```
