# SmugMug API v2 Uploader

## Objectives
- Create top-level folder, create album, and upload image, given a SmugMug account.
- Utilize v2 of the SmugMug API.

## 3rd-Party Dependencies
- `requests`
- `requests_oauthlib`

## Obstacles
- Most python examples I found of API v2 interaction either:
    - Use python2.
    - Use an outdated version of the API.
    - Are bogged down by excessive use of classes.
- The `rauth` OAuth library described in [SmugMug Documentation](https://api.smugmug.com/api/v2/doc/tutorial/oauth/non-web.html) works without issue with the SmugMug API, but not the Uploader API. I ended up using `requests_oauthlib`.

## Use Case
This was mainly written as a Proof-of-Concept to supplement a [DIY Photobooth project](https://github.com/reuterbal/photobooth).