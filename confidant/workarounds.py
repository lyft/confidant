# https://github.com/boto/botocore/issues/760
# https://github.com/boto/boto3/issues/220#issuecomment-171477361
try:
    from botocore.vendored.requests.packages.urllib3.contrib import pyopenssl
    pyopenssl.extract_from_urllib3()
except ImportError:
    pass
