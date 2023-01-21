<template>
  <div class="card mt-5 shadow">
    <div class="card-header d-flex justify-content-between">
      <h4 class="">Book List</h4>
    </div>
    <div class="card-body">
      <div class="row">
        <div v-for="book in books" class="col-md-3 px-3">
          <div class=" shadow  mb-5">
            <img class="img-thumbnail" :src="book.image" style="width: 100%">
            <div class="text-center mt-3">
              <h5>{{ book.name }}</h5>
              <p class="text-muted">{{ book.author_name }}</p>
              <div class="d-flex justify-content-between px-4">
                <h6>
                  <del>TK {{ book.price }}</del>
                </h6>
                <h6>TK {{ book.discount_price }}</h6>
              </div>
            </div>
          </div>
        </div>
      </div>
      <h5 v-if="!books.length" class="mt-4 text-muted text-center">No Books found...</h5>
    </div>
  </div>
</template>

<script>
import ApiService from "@/services/api.service";

export default {
  name: "Dashboard",
  data() {
    return {
      books: []
    }
  },
  mounted() {
    this.getBooks();
  },
  methods: {
    getBooks() {
      ApiService.get('books').then(({data}) => {
        console.log(data)
        this.books = data;
      }).catch(e => console.log(e))
    },
  }
}
</script>

<style scoped>

</style>