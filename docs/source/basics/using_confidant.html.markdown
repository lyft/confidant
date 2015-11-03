---
title: Managing secrets and mappings
---

# Managing secrets and mappings

Confidant is simple; it has two concepts: secrets and the mappings of those
secrets to services. Both secrets and their mappings to services are revisioned
and no revision is ever deleted. Confidant has two views: the resources view
and the history view.

## Using the resources view

### Creating secrets

<img src='/images/interface-create.png' width="200" style="float: left; margin: 10px"></img>

In the left panel of the resources view is the list of secrets and services.
Above that is a filter, and next to the filter is a plus. Clicking on that plus
gives you the option to create a credential or to create a service.

Click on create credential. This will bring up a new credential resource in the
right panel.

Credentials have human readable names, which can be renamed, and a
set of credential pairs. Credential pairs are key/value pairs, where the key is
alphanumeric and the value can be anything. Credential pairs are the secrets
and are encrypted at-rest. The rest of the metadata is stored along with the secret
and is un-encrypted, so the friendly name should not contain anything sensitive.

<img src='/images/interface-new-credential.png' width="350" style="float: right; margin: 10px"></img>

Credentials can have more than a single credential pair; however, it's
important to note that keys must be unique in a credential, and when mapping
credentials to a service, the keys must be unique across all credentials in
the mapped service. This is to avoid confusion on the service's end, where two
conflicting keys would force the service to choose which key is valid.

### Mapping secrets to services

<img src='/images/interface-new-service.png' width="350" style="float: left; margin: 10px"></img>

In the same way you created a new credential, do the same thing, but now click
on create service. This will bring up a new service resourse in the right
panel.

Services in Confidant are extensions of IAM roles, so the new service
name that you create should match the IAM role you wish to map the credentials
with. To make things a bit easier, Confidant will auto-complete the IAM role
name as you type in the service name. Note that Confidant will allow you to
create a service even if an IAM role with the matching name doesn't exist. This
is a feature to allow you to map credentials to a service before it's been
created.

### Finding credentials and services in the sidebar

<img src='/images/interface-filter.png' width="225" style="float: right; margin: 10px"></img>

Once you have enough credentials and services, it can be difficult to find them
in the sidebar. To make this easier, the sidebar has a filter at the top
that'll let you selectively display credentials and services.
<img src='/images/interface-filter-with-regex.png' width="225" style="float: left; margin: 10px"></img>

By default this filter will match any word in the user-defined name of
credentials and services, but it's also possible to use a regex filter instead.

<br>
## Using the history view

<img src='/images/interface-history.png' width="400" style="float: right; margin: 10px"></img>

The history view can be used to explore changes in credentials or services. The
left panel of the history view shows a list of changes, sorted by date.
Clicking on any revision in the left panel will bring up a diff view in the
right panel. In the diff view, you can navigate to older or newer revisions of
the selected resource, or you can revert to a revision of the selected
resource.
