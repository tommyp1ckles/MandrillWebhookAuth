# Mandrill Webhook Auth

Authenticates a Mandrill Webhook POST request.

## Testing

The test doesn't contain the correct authentication data, if you want to
test this yourself you'll need to generate your own data.

You can do this by going to [requestb.in](https://requestb.in/) and creating a
private bin. Then copy the bin URL and use it to create a new webhook in Mandrill. The `authKey` is the key value for the webhook so you can copy that in. Next click
the test event button and refresh your requestbin. Finally copy the `mandrill_events` and `X-Mandrill-Signature` and run the test. 
