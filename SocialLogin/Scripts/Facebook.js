// This is called with the results from from FB.getLoginStatus().
function statusChangeCallback(response) {
    if (response.status === 'connected') {
        // Logged into your app and Facebook.
        var credentials = { uid: response.authResponse.userID, accessToken: response.authResponse.accessToken };
        $.ajax({
            url: "/Home/FacebookLogin",
            type: "POST",
            data: credentials,
            error: function () {
                alert("error logging in to your facebook account.");
            },
            beforeSend: function () {
                $('#dvLoading').removeClass("hidden");
                $('#dvLogin').addClass("hidden");
            },
            success: function (d) {
                if (d.success) {
                    window.location.href = d.url;
                } else {
                    alert("Bạn vui lòng bỏ ẩn email trong cài đặt để đăng ký tài khoản trên Facebook");
                }
            }
        });
    } else if (response.status === 'not_authorized') {
        // The person is logged into Facebook, but not your app.
        alert("user is not authorised");
    } else {
        // The person is not logged into Facebook, so we're not sure if
        // they are logged into this app or not.
        alert("user is not conntected to facebook");
    }
}
