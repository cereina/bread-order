/*
 * Client-side logic for the multi-user Bread Order App.
 *
 * This version of the application does not use localStorage. Instead,
 * it communicates with a server (see server.js) to store orders and
 * available items in JSON files. Multiple users can load the app from
 * the same server and share the same list of orders.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM elements
  const itemNameSelect = document.getElementById('itemNameSelect');
  const itemQtyInput = document.getElementById('itemQty');
  const orderForm = document.getElementById('orderForm');
  const orderItemsList = document.getElementById('orderItems');
  const sendSummaryBtn = document.getElementById('sendSummary');
  const resetOrdersBtn = document.getElementById('resetOrders');
  const itemList = document.getElementById('itemList');
  const addNewItemBtn = document.getElementById('addNewItem');

  // Local copies of remote data
  let orders = [];
  let availableItems = [];
  let editingIndex = null;

  /**
   * Fetch the list of items from the server. On error, fall back to
   * default items. After fetching, update the dropdown and item list.
   */
  async function fetchItems() {
    try {
      const res = await fetch('/api/items');
      if (res.ok) {
        availableItems = await res.json();
      } else {
        throw new Error('Failed to load items');
      }
    } catch (err) {
      console.error(err);
      availableItems = ['Baguette', 'Whole Wheat', 'Rye', 'Sourdough'];
    }
    populateItemSelect();
    renderItemList();
  }

  /**
   * Fetch the current orders from the server. On success, update the
   * local orders array and re-render the order list. On error, set
   * orders to empty.
   */
  async function fetchOrders() {
    try {
      const res = await fetch('/api/orders');
      if (res.ok) {
        orders = await res.json();
      } else {
        throw new Error('Failed to load orders');
      }
    } catch (err) {
      console.error(err);
      orders = [];
    }
    editingIndex = null;
    renderOrders();
  }

  /**
   * Send a POST request to add a new order. Updates the local order list
   * with the response.
   * @param {string} item
   * @param {number} qty
   */
  async function createOrder(item, qty) {
    try {
      const res = await fetch('/api/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item, qty })
      });
      if (res.ok) {
        orders = await res.json();
      } else {
        const msg = await res.json();
        throw new Error(msg.error || 'Failed to add order');
      }
      renderOrders();
    } catch (err) {
      console.error(err);
      alert('Could not add order: ' + err.message);
    }
  }

  /**
   * Send a PUT request to update an existing order. Updates the local
   * orders list with the response.
   * @param {number} index
   * @param {string} item
   * @param {number} qty
   */
  async function updateOrder(index, item, qty) {
    try {
      const res = await fetch(`/api/orders/${index}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item, qty })
      });
      if (res.ok) {
        orders = await res.json();
      } else {
        const msg = await res.json();
        throw new Error(msg.error || 'Failed to update order');
      }
      editingIndex = null;
      renderOrders();
    } catch (err) {
      console.error(err);
      alert('Could not update order: ' + err.message);
    }
  }

  /**
   * Send a DELETE request to remove an order. On success, reload orders
   * from the server.
   * @param {number} index
   */
  async function deleteOrder(index) {
    try {
      const res = await fetch(`/api/orders/${index}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        // Delete succeeded: refresh orders list
        await fetchOrders();
      } else {
        const msg = await res.json();
        throw new Error(msg.error || 'Failed to delete order');
      }
    } catch (err) {
      console.error(err);
      alert('Could not delete order: ' + err.message);
    }
  }

  /**
   * Send a POST request to create a new bread item on the server.
   * On success, reload items list and update UI.
   * @param {string} name
   */
  async function createItem(name) {
    try {
      const res = await fetch('/api/items', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      if (res.ok) {
        availableItems = await res.json();
        populateItemSelect();
        renderItemList();
      } else {
        const msg = await res.json();
        throw new Error(msg.error || 'Failed to add item');
      }
    } catch (err) {
      console.error(err);
      alert('Could not add new item: ' + err.message);
    }
  }

  /**
   * Send a PUT request to rename an existing bread item. The server will
   * handle updating orders that reference the old name. After a
   * successful response, reload items and orders.
   * @param {number} index
   * @param {string} newName
   */
  async function renameItemOnServer(index, newName) {
    try {
      const res = await fetch(`/api/items/${index}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName })
      });
      if (res.ok) {
        availableItems = await res.json();
        // Refresh orders because item names may have changed
        await fetchOrders();
        populateItemSelect();
        renderItemList();
      } else {
        const msg = await res.json();
        throw new Error(msg.error || 'Failed to rename item');
      }
    } catch (err) {
      console.error(err);
      alert('Could not rename item: ' + err.message);
    }
  }

  /**
   * Populate the select element with the current available items.
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
   * Render the list of available items in the Manage Items section. Each
   * entry can be clicked to rename it.
   */
  function renderItemList() {
    itemList.innerHTML = '';
    availableItems.forEach((name, index) => {
      const li = document.createElement('li');
      const span = document.createElement('span');
      span.textContent = name;
      span.title = 'Click to rename';
      span.style.cursor = 'pointer';
      span.addEventListener('click', () => {
        const newName = prompt(`Rename '${name}' to:`, name);
        if (newName === null) return;
        const trimmed = newName.trim();
        if (!trimmed) {
          alert('Item name cannot be empty.');
          return;
        }
        renameItemOnServer(index, trimmed);
      });
      li.appendChild(span);
      itemList.appendChild(li);
    });
  }

  /**
   * Render the list of orders. This function uses the local `orders` array.
   * When editing, it shows a form row; otherwise it shows the order with
   * Edit/Delete buttons. Indices correspond to positions in the `orders` array.
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
        // Editing mode
        const editSelect = document.createElement('select');
        availableItems.forEach(item => {
          const opt = document.createElement('option');
          opt.value = item;
          opt.textContent = item;
          if (item === order.item) opt.selected = true;
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
          if (!newItem || isNaN(newQty) || newQty <= 0) {
            alert('Please enter a valid item and quantity.');
            return;
          }
          updateOrder(index, newItem, newQty);
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
        const span = document.createElement('span');
        span.textContent = `${order.item}: ${order.qty}`;
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
        deleteBtn.addEventListener('click', async () => {
          if (confirm('Delete this order?')) {
            await deleteOrder(index);
          }
        });
        li.appendChild(span);
        li.appendChild(editBtn);
        li.appendChild(deleteBtn);
      }
      orderItemsList.appendChild(li);
    });
  }

  /**
   * Generate a summary of orders and create a mailto link. Since orders are
   * stored on the server, the summary is generated from the local `orders`
   * array. No data is sent to the server when emailing.
   */
  function sendSummary() {
    if (orders.length === 0) {
      alert('No orders to send.');
      return;
    }
    const summary = {};
    orders.forEach(order => {
      summary[order.item] = (summary[order.item] || 0) + order.qty;
    });
    const lines = Object.keys(summary).map(item => `${item}: ${summary[item]}`);
    const body = encodeURIComponent(lines.join('\n'));
    const subject = encodeURIComponent('Daily Bread Order Summary');
    const mailto = `mailto:?subject=${subject}&body=${body}`;
    window.location.href = mailto;
  }

  /**
   * Clear all orders after confirmation by deleting them individually.
   * This uses the server API to remove each order from the back end.
   */
  async function resetOrders() {
    if (orders.length === 0) {
      alert('There are no orders to reset.');
      return;
    }
    if (!confirm('Are you sure you want to clear all orders?')) {
      return;
    }
    // Delete orders from back end one by one starting from the end
    try {
      for (let i = orders.length - 1; i >= 0; i--) {
        const res = await fetch(`/api/orders/${i}`, { method: 'DELETE' });
        if (!res.ok) {
          const msg = await res.json();
          throw new Error(msg.error || 'Failed to delete order');
        }
      }
      // Now reload orders
      await fetchOrders();
    } catch (err) {
      console.error(err);
      alert('Could not reset orders: ' + err.message);
    }
  }

  // Event handlers
  orderForm.addEventListener('submit', async event => {
    event.preventDefault();
    const selectedItem = itemNameSelect.value;
    const qty = parseInt(itemQtyInput.value, 10);
    if (!selectedItem || isNaN(qty) || qty <= 0) {
      alert('Please select a valid item and quantity.');
      return;
    }
    await createOrder(selectedItem, qty);
    itemQtyInput.value = '';
  });
  sendSummaryBtn.addEventListener('click', sendSummary);
  resetOrdersBtn.addEventListener('click', resetOrders);
  addNewItemBtn.addEventListener('click', () => {
    const newName = prompt('Enter new bread item name:');
    if (newName === null) return;
    const trimmed = newName.trim();
    if (!trimmed) {
      alert('Item name cannot be empty.');
      return;
    }
    createItem(trimmed);
  });

  // Initial fetch of data
  fetchItems().then(() => fetchOrders());
});

// Register service worker for offline support
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('service-worker.js')
      .catch(err => {
        console.error('Service worker registration failed:', err);
      });
  });
}