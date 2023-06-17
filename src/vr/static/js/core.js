

function showModal(modal_nm) {
  // Get the modal
  let modal = document.getElementById(modal_nm);
  modal.style.display = "block";
};
function hideModal(modal_nm) {
  // Get the modal
  let modal = document.getElementById(modal_nm);
  modal.style.display = "none";
};

function hasClass(el, className) {
    if (el.classList) {
        return el.classList.contains(className);
    }
    return !!el.className.match(new RegExp('(\\s|^)' + className + '(\\s|$)'));
}
function addClass(el, className) {
    if (el.classList) {
        el.classList.add(className)
    }
    else if (!hasClass(el, className)) {
        el.className += " " + className;
    }
}
function removeClass(el, className) {
    if (el.classList)
        el.classList.remove(className)
    else if (hasClass(el, className))
    {
        let reg = new RegExp('(\\s|^)' + className + '(\\s|$)');
        el.className = el.className.replace(reg, ' ');
    }
}
function addAndRemoveClass(id, a_className, r_className) {
    let el = document.getElementById(id);
    addClass(el, a_className);
    removeClass(el, r_className);
};
function goBack() {
    window.history.back();
  };
function goForward() {
window.history.forward();
};
function toggleTopNav() {
	if (topMenuDrop.style.display === 'block') {
		topMenuDrop.style.display = 'none'
	}
	else {
		topMenuDrop.style.display = 'block'
	}
}
// Get the main section
const mainSect = document.getElementById("main")

// Get the Sidebar
const mySidebar = document.getElementById("mySidebar");

// Get the DIV with overlay effect
const overlayBg = document.getElementById("myOverlay");
function addAndRemoveClassEl(el, a_className, r_className) {
  addClass(el, a_className);
  removeClass(el, r_className);
};
// Toggle between showing and hiding the sidebar, and add overlay effect
function openNav() {
  if (mySidebar.style.display === 'block') {
    mySidebar.style.display = 'none';
    // overlayBg.style.display = "none";
    // mySidebar.style.width = "0px";
    // document.getElementById("main").style.marginLeft = "0px";
    addAndRemoveClassEl(mySidebar, "col_0", "col_3")
    // Eliminate Overlay effect (make column adjust)
    addAndRemoveClassEl(mainSect, "col_0_margin_l", "col_3_margin_l")
  } else {
    mySidebar.style.display = 'block';
    // overlayBg.style.display = "block";
    // mySidebar.style.width = "300px";
    // document.getElementById("main").style.marginLeft = "300px";
    // mySidebar.style.width = "16.66%";
    // document.getElementById("main").style.marginLeft = "16.66%";
    addAndRemoveClassEl(mySidebar, "col_3", "col_0")
    // Eliminate Overlay effect (make column adjust)
    addAndRemoveClassEl(mainSect, "col_3_margin_l", "col_0_margin_l")
  }
}
// Close the sidebar with the close button
function closeNav() {
  mySidebar.style.display = "none";
  overlayBg.style.display = "none";
  document.getElementById("main").style.marginLeft= "0";
}
function menuAnimate(x) {
  x.classList.toggle("change");
}
