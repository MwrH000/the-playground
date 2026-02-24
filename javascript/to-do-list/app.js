const storageKey = "todo-panel-tasks";

const form = document.getElementById("taskForm");
const taskInput = document.getElementById("taskInput");
const deadlineDateInput = document.getElementById("deadlineDateInput");
const taskList = document.getElementById("taskList");
const emptyState = document.getElementById("emptyState");
const taskCount = document.getElementById("taskCount");

let tasks = loadTasks();
render();

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const title = taskInput.value.trim();
  if (!title) return;

  const task = {
    id: crypto.randomUUID(),
    title,
    createdAt: new Date().toISOString(),
    deadline: buildDeadlineISO(deadlineDateInput.value),
    completed: false,
  };

  tasks.unshift(task);
  saveTasks();
  render();

  form.reset();
  taskInput.focus();
});

taskList.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const actionBtn = target.closest("button[data-action]");
  if (!actionBtn) return;

  const { action, id } = actionBtn.dataset;
  const taskIndex = tasks.findIndex((task) => task.id === id);
  if (taskIndex < 0) return;

  if (action === "toggle") {
    tasks[taskIndex].completed = !tasks[taskIndex].completed;
  }

  if (action === "delete") {
    tasks.splice(taskIndex, 1);
  }

  saveTasks();
  render();
});

function render() {
  taskList.innerHTML = "";
  const sortedTasks = [...tasks].sort((a, b) => {
    if (a.completed !== b.completed)
      return Number(a.completed) - Number(b.completed);

    const aDeadline = a.deadline
      ? new Date(a.deadline).getTime()
      : Number.POSITIVE_INFINITY;
    const bDeadline = b.deadline
      ? new Date(b.deadline).getTime()
      : Number.POSITIVE_INFINITY;

    if (aDeadline !== bDeadline) return aDeadline - bDeadline;
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  });

  if (sortedTasks.length === 0) {
    emptyState.classList.remove("hidden");
  } else {
    emptyState.classList.add("hidden");
  }

  for (const task of sortedTasks) {
    const item = document.createElement("li");
    item.className = `task-item${task.completed ? " completed" : ""}`;

    const createdText = formatDate(task.createdAt);
    const deadlineText = task.deadline
      ? formatDate(task.deadline, false)
      : "No deadline";
    const overdue = isOverdue(task.deadline, task.completed);

    item.innerHTML = `
      <div class="task-row">
        <p class="task-title">${escapeHtml(task.title)}</p>
        <div class="actions">
          <button class="icon-btn" data-action="toggle" data-id="${task.id}">
            ${task.completed ? "Undo" : "Complete"}
          </button>
          <button class="icon-btn delete" data-action="delete" data-id="${task.id}">Delete</button>
        </div>
      </div>
      <div class="task-meta">
        <span class="badge">Added: ${createdText}</span>
        <span class="badge deadline${overdue ? " overdue" : ""}">Deadline: ${deadlineText}</span>
      </div>
    `;

    taskList.appendChild(item);
  }

  const activeCount = tasks.filter((task) => !task.completed).length;
  taskCount.textContent = `${activeCount} active`;
}

function loadTasks() {
  try {
    const raw = localStorage.getItem(storageKey);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveTasks() {
  localStorage.setItem(storageKey, JSON.stringify(tasks));
}

function formatDate(isoString, withTime = true) {
  if (!isoString) return "";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "Invalid date";

  const options = {
    year: "numeric",
    month: "short",
    day: "2-digit",
  };

  if (withTime) {
    options.hour = "2-digit";
    options.minute = "2-digit";
  }

  return new Intl.DateTimeFormat(undefined, options).format(date);
}

function isOverdue(deadlineIso, completed) {
  if (!deadlineIso || completed) return false;
  const deadline = new Date(deadlineIso).getTime();
  if (Number.isNaN(deadline)) return false;
  return Date.now() > deadline;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function buildDeadlineISO(dateValue) {
  if (!dateValue) return "";
  const combined = `${dateValue}T23:59`;
  const date = new Date(combined);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}
