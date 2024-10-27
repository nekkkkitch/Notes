async function AddNote(){
    var accessToken = getCookie("accessToken")
    var refreshToken = getCookie("refreshToken")
    var title = document.getElementById("title").value
    var description = document.getElementById("description").value
    var query = new URLSearchParams(window.location.search)
    let response = await fetch('/add-note',{
        method:'POST',
        headers:{
            'x-access-token':accessToken,
            'x-refresh-token':refreshToken
        },
        body: JSON.stringify({
            'Title':title,
            'Description':description
        })
    })
    var commit = await response.json()
    if(CheckStatus(commit)){
        window.location.replace("http://localhost:8080")
    }
}

function CheckStatus(commit){
    var status = document.getElementById("status")
    switch(commit.status){
        case "User is not identified":
            status.textContent = "Вы не вошли в аккаунт"
            return false
        case "Invalid token":
            status.textContent = "Токен был изменён, перезайдите в аккаунт"
            return false
        case "Expired token":
            status.textContent = "Истёк срок логина. Авторизируйтесь снова"
            return false
        case "Success with tokens":
            var accessToken = commit.accessToken
            var refreshToken = commit.refreshToken
            document.cookie = encodeURIComponent("accessToken") + "=" + encodeURIComponent(accessToken)
            document.cookie = encodeURIComponent("refreshToken") + "=" + encodeURIComponent(refreshToken)
            return true
        case "Success":
            return true
        default:
            status.textContent = commit.status
            return false

    }
}

function getCookie(cname) {
    let name = cname + "=";
    let decodedCookie = decodeURIComponent(document.cookie);
    let ca = decodedCookie.split(';');
    for(let i = 0; i <ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) == ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
}
