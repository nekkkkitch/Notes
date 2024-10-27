GetNote()

async function ChangeNote(){
    var accessToken = getCookie("accessToken")
    var refreshToken = getCookie("refreshToken")
    var title = document.getElementById("title").value
    var description = document.getElementById("description").value
    var query = new URLSearchParams(window.location.search)
    let response = await fetch('/change-note?id='+query.get('id'),{
        method:'PUT',
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

async function GetNote(){
    var accessToken = getCookie("accessToken")
    var refreshToken = getCookie("refreshToken")
    var query = new URLSearchParams(window.location.search)
    let response = await fetch('/get-note?id='+query.get('id'), {
        method:'GET',
        headers:{
            'x-access-token':accessToken,
            'x-refresh-token':refreshToken
        }
    })
    let commit = await response.json()
    if(CheckStatus(commit)){
        ParseNote(commit.note)
    }
}

function ParseNote(note){
    var parsedNote = JSON.parse(atob(note))
    console.log(parsedNote)
    var title = document.getElementById("title")
    var description = document.getElementById("description")
    title.textContent = parsedNote.Title
    description.textContent = parsedNote.Description
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
