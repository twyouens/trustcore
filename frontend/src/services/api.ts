import axios from 'axios';
import { message } from 'antd';

const api = axios.create({
  baseURL: 'http://localhost:8000/api/v1',
});

// Request interceptor - add token to all requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('trustcore_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - handle errors globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const status = error.response.status;
      const errorMessage = error.response.data?.detail || error.response.data?.message || 'An error occurred';

      switch (status) {
        case 401:
          message.error('Unauthorized. Please login again.');
          localStorage.removeItem('trustcore_token');
          window.location.href = '/login';
          break;
        case 403:
          message.error('You do not have permission to perform this action.');
          break;
        case 404:
          message.error('Resource not found.');
          break;
        case 422:
          message.error('Validation error: ' + errorMessage);
          break;
        case 500:
          message.error('Internal server error. Please try again later.');
          break;
        default:
          message.error(errorMessage);
      }
    } else if (error.request) {
      message.error('Network error. Please check your connection.');
    } else {
      message.error('An unexpected error occurred.');
    }

    return Promise.reject(error);
  }
);

export default api;