const modal = document.getElementById('modal');

const selectMember = (member) => {
  const {email, password} = member;
  const token = `${email}:${password}`;
  const encodedToken = btoa(token);
  localStorage.setItem('credentials', encodedToken);
  alert(`${email} 사용자로 설정 했습니다.`);

  axios.request({
    url: `/`,
    method: 'GET',
    headers: {
      'Authorization': `Basic ${encodedToken}`
    },
  }).then((response) => {
    window.location.href = '/'
  }).catch((error) => {
    console.error(error);
  });
}

const showMemberInfo = (memberId) => {
  window.location.href = `/member/${memberId}`
}

const showUserAddModal = () => {
  modal.dataset.formType = 'add';
  modal.style.display = 'block';
};

const hideUserAddModal = () => {
  modal.style.display = 'none';
  const elements = modal.getElementsByTagName('input');
  for (const element of elements) {
    element.value = '';
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();

  const formData = new FormData(event.target);
  let user = {};

  for (const entry of formData.entries()) {
    const [key, value] = entry;
    user[key] = value;
  }

  createUser(user);
});

const createUser = (user) => {
  axios.post('/member', user)
  .then((response) => {
    window.location.reload();
  }).catch((error) => {
    const {data} = error.response;
    window.alert(data.errorMessage)
  });
};
