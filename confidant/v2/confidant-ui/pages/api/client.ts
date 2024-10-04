class ConfidantClient {
    healthcheck(){
        var url = `${process.env.CONFIDANT_BASE_URL}/healthcheck`
        return fetch(url)
    }
}

export default ConfidantClient;
