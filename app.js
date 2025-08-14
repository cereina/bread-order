/*
 * Main JavaScript for the Bread Order App.
 *
 * This script manages a simple ordering system for bread items. It provides a
 * dropdown (combo box) of available bread items, allows users to add new
 * items or rename existing ones, and supports adding, editing and deleting
 * individual orders. Orders and the list of available items are stored in
 * localStorage so that they persist across page reloads. At the end of the
 * day you can generate a grouped summary of all orders and open your
 * default email client to send it to the invoicing team.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Storage keys
  const ORDERS_KEY = 'breadOrders';
  const ITEMS_KEY = 'availableItems';

  // DOM elements
  const itemNameSelect = document.getElementById('itemNameSelect');
  const itemQtyInput = document.getElementById('itemQty');
  const orderForm = document.getElementById('orderForm');
  const orderItemsList = document.getElementById('orderItems');
  const sendSummaryBtn = document.getElementById('sendSummary');
  const resetOrdersBtn = document.getElementById('resetOrders');
  const itemList = document.getElementById('itemList');
  const addNewItemBtn = document.getElementById('addNewItem');

  // In‑memory state
  let orders = loadOrders();
  let availableItems = loadAvailableItems();
  let editingIndex = null; // index of order currently being edited

  /**
   * Load orders from localStorage. If none exist, return an empty array.
   * @returns {Array<{item: string, qty: number}>}
   */
  function loadOrders() {
    try {
      const stored = localStorage.getItem(ORDERS_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (err) {
      console.error('Failed to parse orders from localStorage:', err);
    }
    return [];
  }

  /**
   * Persist the current orders to localStorage.
   */
  function saveOrders() {
    localStorage.setItem(ORDERS_KEY, JSON.stringify(orders));
  }

  /**
   * Load the list of available items from localStorage or initialise with
   * sensible defaults. Defaults are only used on first visit.
   * @returns {string[]}
   */
  function loadAvailableItems() {
    try {
      const stored = localStorage.getItem(ITEMS_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (err) {
      console.error('Failed to parse available items from localStorage:', err);
    }
    // Default items – feel free to customise
    return ['Baguette', 'Whole Wheat', 'Rye', 'Sourdough'];
  }

  /**
   * Persist the current list of available items to localStorage.
   */
  function saveAvailableItems() {
    localStorage.setItem(ITEMS_KEY, JSON.stringify(availableItems));
  }

  /**
   * Populate the select element with the current available items. Clears any
   * existing options before adding new ones. If possible, preserves the
   * current selection.
   */
  function populateItemSelect() {
    const previousValue = itemNameSelect.value;
    itemNameSelect.innerHTML = '';
    availableItems.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item;
      opt.textContent = item;
      if (item === previousValue) {
        opt.selected = true;
      }
      itemNameSelect.appendChild(opt);
    });
  }

  /**
   * Render the list of available items inside the Manage Items section. Each
   * list item includes a button that allows the user to rename that item.
   */
  function renderItemList() {
    itemList.innerHTML = '';
    availableItems.forEach((name, index) => {
      const li = document.createElement('li');
      const span = document.createElement('span');
      span.textContent = name;
      span.title = 'Click to rename';
      span.style.cursor = 'pointer';
      span.addEventListener('click', () => renameItem(index));
      li.appendChild(span);
      itemList.appendChild(li);
    });
  }

  /**
   * Prompt the user to rename an item. If the new name is valid (non‑empty and
   * not already taken), update both the availableItems array and any existing
   * orders that reference the old name. Changes are persisted and the
   * interface is re-rendered.
   * @param {number} index Index of the item to rename
   */
  function renameItem(index) {
    const oldName = availableItems[index];
    const newName = prompt(`Rename '${oldName}' to:`, oldName);
    if (newName === null) {
      return; // user cancelled
    }
    const trimmed = newName.trim();
    if (!trimmed) {
      alert('Item name cannot be empty.');
      return;
    }
    if (availableItems.includes(trimmed) && trimmed !== oldName) {
      alert('That item name already exists.');
      return;
    }
    availableItems[index] = trimmed;
    // Update any orders referencing oldName
    orders = orders.map(order => {
      if (order.item === oldName) {
        return { item: trimmed, qty: order.qty };
      }
      return order;
    });
    saveAvailableItems();
    saveOrders();
    populateItemSelect();
    renderItemList();
    renderOrders();
  }

  /**
   * Prompt the user to add a new bread item. Ensures the item name is
   * non‑empty and unique. If valid, adds the item to the list and refreshes
   * the dropdown and item list.
   */
  function addNewItem() {
    const newItem = prompt('Enter new bread item name:');
    if (newItem === null) {
      return; // cancelled
    }
    const trimmed = newItem.trim();
    if (!trimmed) {
      alert('Item name cannot be empty.');
      return;
    }
    if (availableItems.includes(trimmed)) {
      alert('That item already exists.');
      return;
    }
    availableItems.push(trimmed);
    saveAvailableItems();
    populateItemSelect();
    renderItemList();
  }

  /**
   * Render the current list of orders. Each list item shows the order and
   * provides Edit and Delete buttons. When an order is being edited, the
   * corresponding list item is replaced by an inline form allowing the user
   * to change the item or quantity and either save or cancel the changes.
   */
  function renderOrders() {
    orderItemsList.innerHTML = '';
    if (orders.length === 0) {
      const emptyLi = document.createElement('li');
      emptyLi.textContent = 'No orders yet.';
      orderItemsList.appendChild(emptyLi);
      return;
    }
    orders.forEach((order, index) => {
      const li = document.createElement('li');
      if (editingIndex === index) {
        // Editing mode: show a form row to edit this order
        const editSelect = document.createElement('select');
        availableItems.forEach(item => {
          const opt = document.createElement('option');
          opt.value = item;
          opt.textContent = item;
          if (item === order.item) {
            opt.selected = true;
          }
          editSelect.appendChild(opt);
        });
        const editQty = document.createElement('input');
        editQty.type = 'number';
        editQty.min = '1';
        editQty.value = order.qty;
        editQty.style.width = '4rem';
        const saveBtn = document.createElement('button');
        saveBtn.type = 'button';
        saveBtn.textContent = 'Save';
        saveBtn.addEventListener('click', () => {
          const newItem = editSelect.value;
          const newQty = parseInt(editQty.value, 10);
          if (!newItem || newQty <= 0 || Number.isNaN(newQty)) {
            alert('Please enter a valid item and quantity.');
            return;
          }
          orders[index] = { item: newItem, qty: newQty };
          editingIndex = null;
          saveOrders();
          renderOrders();
        });
        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.addEventListener('click', () => {
          editingIndex = null;
          renderOrders();
        });
        li.appendChild(editSelect);
        li.appendChild(editQty);
        li.appendChild(saveBtn);
        li.appendChild(cancelBtn);
      } else {
        // Display mode: show the order and Edit/Delete buttons
        const textSpan = document.createElement('span');
        textSpan.textContent = `${order.item}: ${order.qty}`;
        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.textContent = 'Edit';
        editBtn.addEventListener('click', () => {
          editingIndex = index;
          renderOrders();
        });
        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', () => {
          if (confirm('Delete this order?')) {
            orders.splice(index, 1);
            // If we deleted an order before the one currently being edited,
            // adjust the editing index accordingly
            if (editingIndex !== null && index < editingIndex) {
              editingIndex--;
            }
            saveOrders();
            renderOrders();
          }
        });
        li.appendChild(textSpan);
        li.appendChild(editBtn);
        li.appendChild(deleteBtn);
      }
      orderItemsList.appendChild(li);
    });
  }

  /**
   * Generate a grouped summary of all orders and open a mailto link to send
   * this summary via email. Groups duplicate items and totals their
   * quantities. The subject and body are URL encoded as required for
   * mailto links.
   */
  function sendSummary() {
    if (orders.length === 0) {
      alert('No orders to send.');
      return;
    }
    // Aggregate quantities per item
    const summary = {};
    orders.forEach(order => {
      summary[order.item] = (summary[order.item] || 0) + order.qty;
    });
    // Build email body lines
    const lines = Object.keys(summary).map(item => `${item}: ${summary[item]}`);
    const body = encodeURIComponent(lines.join('\n'));
    const subject = encodeURIComponent('Daily Bread Order Summary');
    // Note: The recipient can be pre-filled here, e.g., mailto:orders@example.com
    const mailto = `mailto:?subject=${subject}&body=${body}`;
    window.location.href = mailto;
  }

  /**
   * Clear all orders after user confirmation.
   */
  function resetOrders() {
    if (orders.length === 0) {
      alert('There are no orders to reset.');
      return;
    }
    if (confirm('Are you sure you want to clear all orders?')) {
      orders = [];
      editingIndex = null;
      saveOrders();
      renderOrders();
    }
  }

  // Event listeners
  orderForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const selectedItem = itemNameSelect.value;
    const qty = parseInt(itemQtyInput.value, 10);
    if (!selectedItem || Number.isNaN(qty) || qty <= 0) {
      alert('Please select a valid item and quantity.');
      return;
    }
    if (editingIndex !== null) {
      // If we were editing an order but user submitted via the form, treat
      // this as adding a new order (reset editing state first)
      editingIndex = null;
    }
    orders.push({ item: selectedItem, qty: qty });
    saveOrders();
    itemQtyInput.value = '';
    renderOrders();
  });
  sendSummaryBtn.addEventListener('click', sendSummary);
  resetOrdersBtn.addEventListener('click', resetOrders);
  addNewItemBtn.addEventListener('click', addNewItem);

  // Initial render
  populateItemSelect();
  renderItemList();
  renderOrders();
});