export default function ({
    $axios,
    redirect
}) {
    $axios.onError(error => {
        window.location.reload();
    })
}